package awsglue

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"context"
	goerr "errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

type SyncTask struct {
	DryRun      bool
	NumRequests int
	Logger      *zap.Logger
	Start       time.Time
	End         time.Time
	GlueClient  glueiface.GlueAPI
	S3Client    s3iface.S3API
}

// ScanTables returns a list of available tables in the log processing database
func (s *SyncTask) ScanTables(ctx context.Context, dbName string, match *regexp.Regexp) ([]*glue.TableData, error) {
	var tables []*glue.TableData
	scanPage := func(page *glue.GetTablesOutput, _ bool) bool {
		tables = append(tables, page.TableList...)
		return true
	}
	input := &glue.GetTablesInput{
		DatabaseName: aws.String(dbName),
	}
	if match != nil {
		input.Expression = aws.String(match.String())
	}
	if err := s.GlueClient.GetTablesPagesWithContext(ctx, input, scanPage); err != nil {
		return nil, err
	}
	return tables, nil
}

type PartitionScanFunc func(p *glue.GetPartitionsOutput, isLast bool) bool

// ScanPartitions scans all Glue partitions in a time range
func (s *SyncTask) ScanPartitions(ctx context.Context, lastToken string, tbl *glue.TableData, scan PartitionScanFunc) error {
	bin, err := TimebinFromTable(tbl)
	if err != nil {
		return err
	}
	input := glue.GetPartitionsInput{
		CatalogId:    tbl.CatalogId,
		TableName:    tbl.Name,
		DatabaseName: tbl.DatabaseName,
	}
	if lastToken != "" {
		input.NextToken = &lastToken
	}
	start, end := s.Start, s.End
	if end.IsZero() {
		end = time.Now()
	}
	scanRange := ScanRange{
		Start: start,
		End:   end,
	}
	if expr := scanRange.PartitionFilter(bin); expr != "" {
		input.Expression = &expr
	}
	return s.GlueClient.GetPartitionsPagesWithContext(ctx, &input, scan)
}

func (s *SyncTask) SyncDatabase(ctx context.Context, dbName string, matchTable *regexp.Regexp) (out SyncSummary, err error) {
	log := s.log(&dbName, nil)
	if matchTable != nil {
		log = log.With(zap.String("match", matchTable.String()))
	}
	log.Info("scanning for tables")
	tables, err := s.ScanTables(ctx, dbName, matchTable)
	if err != nil {
		log.Error("table scan failed", zap.Error(err))
		return out, err
	}
	log.Info("scanning for tables complete", zap.Int("numTables", len(tables)))
	if len(tables) == 0 {
		log.Info("no tables found")
		return out, nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(tables))
	tblResults := make([]SyncSummary, len(tables))
	tblErrors := make([]error, len(tables))
	for i, tbl := range tables {
		tbl := tbl
		tblResult := &tblResults[i]
		tblError := &tblErrors[i]
		go func() {
			defer wg.Done()
			r, err := s.SyncTable(ctx, tbl, "")
			*tblError = err
			if r != nil {
				*tblResult = *r
			}
		}()
	}
	wg.Wait()
	for _, r := range tblResults {
		out = CombineSyncSummaries(out, r)
	}
	for _, e := range tblErrors {
		err = multierr.Append(err, e)
	}
	return out, err
}

// SyncTable scans all Glue partitions in a time range and updates their descriptors to match the table descriptor.
func (s *SyncTask) SyncTable(ctx context.Context, tbl *glue.TableData, nextToken string) (*SyncSummary, error) {
	bin, err := TimebinFromTable(tbl)
	if err != nil {
		return nil, err
	}
	log := s.log(tbl.DatabaseName, tbl.Name)
	log.Info("syncing table")
	result := SyncSummary{
		NextToken: nextToken,
	}
	// Scan partitions
	scanError := s.ScanPartitions(ctx, nextToken, tbl, func(page *glue.GetPartitionsOutput, _ bool) bool {
		result.NumPages++
		for _, p := range page.Partitions {
			tm, ok := partitionTime(bin, p)
			if !ok {
				log.Warn("invalid partition key", zap.Strings("values", aws.StringValueSlice(p.Values)))
				continue
			}
			result.ObservePartition(tm)
			if !needsUpdate(tbl, p) {
				log.Debug("skipping partition", zap.Time("time", tm), zap.String("reason", "up-to-date"))
				continue
			}
			result.NumDiff++
			if s.DryRun {
				log.Debug("skipping partition", zap.Time("time", tm), zap.String("reason", "dry-run"))
				continue
			}
			log.Info("syncing partition", zap.Time("time", tm))
			if err := s.syncPartition(ctx, tbl, p); err != nil {
				log.Error("partition sync failed", zap.Time("time", tm), zap.Error(err))
				result.syncErrors = append(result.syncErrors, err)
			} else {
				result.NumSynced++
			}
		}
		// Only update next token if all partitions synced ok
		if len(result.syncErrors) == 0 {
			result.NextToken = aws.StringValue(page.NextToken)
		}
		log.Info("partitions synced", zap.Any("progress", result))
		return true
	})
	if scanError != nil {
		log.Error("failed to scan partitions", zap.Error(scanError))
	}
	log.Debug("sync complete", zap.Any("syncResult", &result))
	return &result, multierr.Append(scanError, result.Err())
}

func (s *SyncTask) syncPartition(ctx context.Context, tbl *glue.TableData, p *glue.Partition) error {
	desc := *p.StorageDescriptor
	desc.Columns = tbl.StorageDescriptor.Columns
	input := glue.UpdatePartitionInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		PartitionInput: &glue.PartitionInput{
			LastAccessTime:    p.LastAccessTime,
			LastAnalyzedTime:  p.LastAnalyzedTime,
			Parameters:        p.Parameters,
			StorageDescriptor: &desc,
			Values:            p.Values,
		},
		PartitionValueList: p.Values,
		TableName:          tbl.Name,
	}
	_, err := s.GlueClient.UpdatePartitionWithContext(ctx, &input)
	return err
}

func needsUpdate(tbl *glue.TableData, p *glue.Partition) bool {
	want := tbl.StorageDescriptor.Columns
	have := p.StorageDescriptor.Columns
	//s.Logger.Debug("diff", zap.Any("colsWant", want), zap.Any("colsHave", have))
	if len(want) != len(have) {
		return true
	}
	return !reflect.DeepEqual(want, have)
}

// FindS3PartitionAt scans S3 to find partition data at the specified time.
func (s *SyncTask) FindS3PartitionAt(ctx context.Context, tbl *glue.TableData, tm time.Time) (string, error) {
	bin, err := TimebinFromTable(tbl)
	if err != nil {
		return "", err
	}
	bucket, tblPrefix, err := ParseS3URL(*tbl.StorageDescriptor.Location)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to parse S3 path for table %q", aws.StringValue(tbl.Name))
	}
	objPrefix := path.Join(tblPrefix, bin.PartitionS3PathFromTime(tm)) + "/"
	listObjectsInput := s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(objPrefix),
	}
	hasData := false
	onPage := func(page *s3.ListObjectsV2Output, isLast bool) bool {
		for _, obj := range page.Contents {
			if aws.Int64Value(obj.Size) > 0 {
				hasData = true
				return false
			}
		}
		return true
	}
	if err := s.S3Client.ListObjectsV2PagesWithContext(ctx, &listObjectsInput, onPage); err != nil {
		return "", err
	}
	if !hasData {
		return "", errors.Wrapf(errS3ObjectNotFound, "no partition data for %q at %s", aws.StringValue(tbl.Name), tm)
	}
	return fmt.Sprintf("s3://%s/%s", bucket, objPrefix), nil
}

var errS3ObjectNotFound = goerr.New("s3 object not found")

// RecoverPartitionAt tries to recover a Glue partition by scanning S3 for data.
func (s *SyncTask) RecoverPartitionAt(ctx context.Context, tbl *glue.TableData, tm time.Time) (*glue.Partition, bool, error) {
	bin, err := TimebinFromTable(tbl)
	if err != nil {
		return nil, false, err
	}
	s3Location, err := s.FindS3PartitionAt(ctx, tbl, tm)
	if err != nil {
		return nil, false, err
	}
	desc := *tbl.StorageDescriptor // copy because we will mutate
	desc.Location = aws.String(s3Location)
	partitionValues := bin.PartitionValuesFromTime(tm)
	createPartitionInput := glue.CreatePartitionInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		PartitionInput: &glue.PartitionInput{
			Values:            partitionValues,
			StorageDescriptor: &desc,
		},
	}
	p := &glue.Partition{
		CatalogId:         tbl.CatalogId,
		DatabaseName:      tbl.DatabaseName,
		StorageDescriptor: &desc,
		TableName:         tbl.Name,
		Values:            partitionValues,
	}
	// Do not create new partitions if we're on a dry run
	if s.DryRun {
		return p, false, nil
	}
	if _, err = s.GlueClient.CreatePartitionWithContext(ctx, &createPartitionInput); err != nil {
		// Someone else might have created the partition since we last called FindPartitionAt
		if IsAlreadyExistsError(err) {
			return nil, false, err
		}
		return p, false, err
	}
	return p, true, nil
}

// IsEntityNotFoundError checks if an AWS error has an EntityNotFoundException code.
func IsEntityNotFoundError(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		return awsErr.Code() == glue.ErrCodeEntityNotFoundException
	}
	return false
}

// IsAlreadyExistsError checks if an AWS error has an AlreadyExistsException code.
func IsAlreadyExistsError(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		return awsErr.Code() == glue.ErrCodeAlreadyExistsException
	}
	return false
}

func (s *SyncTask) log(dbName, tblName *string) *zap.Logger {
	log := s.Logger
	if log == nil {
		log = zap.NewNop()
	}
	if dbName != nil {
		log = log.With(zap.String("databaseName", *dbName))
	}
	if tblName != nil {
		log = log.With(zap.String("tableName", *tblName))
	}
	if !s.Start.IsZero() {
		log = log.With(zap.Time("start", s.Start.UTC()))
	}
	if !s.End.IsZero() {
		log = log.With(zap.Time("end", s.End.UTC()))
	}
	return log
}

func newWaitGroup(n int) (*sync.WaitGroup, int) {
	if n < 1 {
		n = 1
	}
	wg := &sync.WaitGroup{}
	wg.Add(n)
	return wg, n
}

type ScanRange struct {
	Start time.Time
	End   time.Time
}

func (s *ScanRange) PartitionFilter(tb GlueTableTimebin) string {
	if s.Start.IsZero() && s.End.IsZero() {
		return ""
	}
	if s.Start.IsZero() {
		return tb.PartitionsBefore(s.End.UTC())
	}
	if s.End.IsZero() {
		return tb.PartitionsAfter(s.Start.UTC())
	}
	return tb.PartitionsBetween(s.Start.UTC(), s.End.UTC())
}

func (s *SyncTask) ScanDatePartitions(ctx context.Context, tbl *glue.TableData, tm time.Time) (map[time.Time]*glue.Partition, error) {
	bin, err := TimebinFromTable(tbl)
	if err != nil {
		return nil, err
	}
	tm = tm.UTC()
	filter := fmt.Sprintf(`year = %d AND month = %d AND day = %d`, tm.Year(), tm.Month(), tm.Day())
	reply, err := s.GlueClient.GetPartitionsWithContext(ctx, &glue.GetPartitionsInput{
		DatabaseName: tbl.DatabaseName,
		TableName:    tbl.Name,
		Expression:   &filter,
	})
	if err != nil {
		return nil, err
	}
	partitions := make(map[time.Time]*glue.Partition, 24)
	for _, p := range reply.Partitions {
		tm, ok := partitionTime(bin, p)
		if !ok {
			continue
		}
		partitions[tm] = p
	}
	return partitions, nil
}

// Recover date tries to recover Glue partitions for a specific date
func (s *SyncTask) RecoverDate(ctx context.Context, tbl *glue.TableData, tm time.Time) (*RecoverResult, error) {
	partitions, err := s.ScanDatePartitions(ctx, tbl, tm)
	if err != nil {
		return nil, err
	}
	if len(partitions) == 24 {
		return nil, err
	}
	start := GlueTableDaily.Truncate(tm)
	end := GlueTableDaily.Next(start)

	var recover []*glue.PartitionInput
	// Iterate over each hour in the day
	for tm := start; tm.Before(end); tm = GlueTableHourly.Next(tm) {
		// Skip an hour if a partition already exists
		if _, ok := partitions[tm]; ok {
			continue
		}
		// Check to see if there are data for this partition in S3
		location, err := s.FindS3PartitionAt(ctx, tbl, tm)
		if err != nil {
			// No data found, skip to the next hour
			if errors.Is(err, errS3ObjectNotFound) {
				continue
			}
			return nil, err
		}
		// We found a partition to be recovered
		desc := *tbl.StorageDescriptor
		desc.Location = aws.String(location)
		recover = append(recover, &glue.PartitionInput{
			StorageDescriptor: &desc,
			Values:            GlueTableHourly.PartitionValuesFromTime(tm),
		})
	}

	result := RecoverResult{
		StartDate: start,
		EndDate:   end,
	}

	if len(recover) == 0 {
		return &result, nil
	}

	// RecoverTable all partitions with a single API call
	reply, err := s.GlueClient.BatchCreatePartitionWithContext(ctx, &glue.BatchCreatePartitionInput{
		CatalogId:          tbl.CatalogId,
		DatabaseName:       tbl.DatabaseName,
		TableName:          tbl.Name,
		PartitionInputList: recover,
	})
	if err != nil {
		result.NumFailed = len(recover)
		return &result, errors.Wrapf(err, "failed to recover %d partitions", len(recover))
	}
	result.NumRecovered = len(recover)
	// Collect errors
	for _, e := range reply.Errors {
		// Decrement recovered
		result.NumRecovered--
		// This will ignore AlreadyExists errors
		if e := s.recoverError(e); e != nil {
			result.NumFailed++
			err = multierr.Append(err, e)
		}
	}
	return &result, err
}

// RecoverResult summarizes the results of a recover task
type RecoverResult struct {
	StartDate    time.Time
	EndDate      time.Time
	NumRecovered int
	NumFailed    int
}

func (s *SyncTask) recoverError(p *glue.PartitionError) error {
	if p == nil || p.ErrorDetail == nil {
		return nil
	}
	code := aws.StringValue(p.ErrorDetail.ErrorCode)
	if code == glue.ErrCodeAlreadyExistsException {
		return nil
	}
	message := aws.StringValue(p.ErrorDetail.ErrorMessage)
	tm, _ := GlueTableHourly.PartitionTimeFromValues(aws.StringValueSlice(p.PartitionValues))
	// Using fmt.Errorf to not add stack
	err := fmt.Errorf("failed to recover Glue partition at %s", tm)
	return awserr.New(code, message, err)
}

func (s *SyncTask) RecoverDatabase(ctx context.Context, dbName string, match *regexp.Regexp) (*RecoverResult, error) {
	log := s.log(&dbName, nil)
	log.Info("scanning for tables", zap.String("match", match.String()))
	tables, err := s.ScanTables(ctx, dbName, match)
	if err != nil {
		log.Error("table scan failed", zap.Error(err))
		return nil, err
	}
	log.Info("scanning for tables complete", zap.Int("numTables", len(tables)))
	summary := RecoverResult{}
	var allErr error
	for _, tbl := range tables {
		result, err := s.RecoverTable(ctx, tbl)
		if result != nil {
			summary = CombineRecoverResults(summary, *result)
		}
		if err != nil {
			allErr = multierr.Append(allErr, err)
		}
	}
	return &summary, allErr
}

// RecoverTable tries to restore partitions at a time range
// It first scans the Glue partitions to know which ones already exist between start and end.
// It then iterates through the time range and scans the table's S3 bucket for objects matching the partitions of the
// missing timestamps.
func (s *SyncTask) RecoverTable(ctx context.Context, tbl *glue.TableData) (*RecoverResult, error) {
	scanRange, err := buildRecoverRange(tbl, s.Start, s.End)
	if err != nil {
		return nil, err
	}

	log := s.log(tbl.DatabaseName, tbl.Name)
	type taskResult struct {
		Result *RecoverResult
		Err    error
	}
	// Start parallel workers for each day
	tasks := make(chan time.Time)
	wg, numWorkers := newWaitGroup(s.NumRequests)
	// Collect worker results in this channel
	results := make(chan *taskResult, numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func(tasks <-chan time.Time) {
			defer wg.Done()
			for tm := range tasks {
				log.Info("recovering data", zap.Time("time", tm))
				r, err := s.RecoverDate(ctx, tbl, tm)
				if err != nil {
					log.Info("recover failed", zap.Error(err), zap.Time("time", tm))
				}
				results <- &taskResult{
					Result: r,
					Err:    err,
				}
			}
		}(tasks)
	}
	go func() {
		// NOTE: Order of defer items is reverse
		// 3. Close result channel once all workers have finished
		defer close(results)
		// 2. Wait for workers to finish
		defer wg.Wait()
		// 1. Close the tasks channel so worker loops stop
		defer close(tasks)

		// Send tasks to workers
		for tm := scanRange.Start; tm.Before(scanRange.End); tm = GlueTableDaily.Next(tm) {
			select {
			case tasks <- tm:
			case <-ctx.Done():
				// Update the range to reflect the range that got processed
				scanRange.End = tm
				return
			}
		}
	}()

	// Collect results
	out := RecoverResult{}
	for r := range results {
		if r.Result != nil {
			out = CombineRecoverResults(out, *r.Result)
		}
		err = multierr.Append(err, r.Err)
	}
	// Set the processed range
	out.StartDate = scanRange.Start
	out.EndDate = scanRange.End
	return &out, err
}

// ScanSummary summarizes the results of a Glue partition scan
type ScanSummary struct {
	// Number of partitions in the table
	NumPartitions int64
	// Number of partition pages during scan
	NumPages int64
	// Min partition time
	MinTime time.Time
	// Max partition time
	MaxTime time.Time
}

func (r *ScanSummary) ObserveMinTime(tm time.Time) {
	if r.MinTime.IsZero() || r.MinTime.After(tm) {
		r.MinTime = tm
	}
}
func (r *ScanSummary) ObserveMaxTime(tm time.Time) {
	if r.MaxTime.Before(tm) {
		r.MaxTime = tm
	}
}

func (r *ScanSummary) ObservePartition(tm time.Time) {
	r.NumPartitions++
	r.ObserveMaxTime(tm)
	r.ObserveMinTime(tm)
}

func partitionTime(bin GlueTableTimebin, p *glue.Partition) (time.Time, bool) {
	return bin.PartitionTimeFromValues(aws.StringValueSlice(p.Values))
}

// SyncSummary summarizes the results of a sync task
type SyncSummary struct {
	ScanSummary
	// Number of partitions with different columns from table
	NumDiff int64
	// Number of partitions synced successfully
	NumSynced int64
	// Last partition scan token successfully synced
	NextToken string
	// Accumulate all sync errors here
	syncErrors []error
}

// CombineSyncSummaries aggregates sync summaries
func CombineRecoverResults(results ...RecoverResult) (out RecoverResult) {
	for _, r := range results {
		out.NumFailed += r.NumFailed
		out.NumRecovered += r.NumRecovered
	}
	return
}

// CombineSyncSummaries aggregates sync summaries
func CombineSyncSummaries(results ...SyncSummary) (out SyncSummary) {
	for _, r := range results {
		out.NumSynced += r.NumSynced
		out.NumDiff += r.NumDiff
		out.NumPages += r.NumPages
		out.NumPartitions += r.NumPartitions
		out.syncErrors = append(out.syncErrors, r.syncErrors...)
		out.ObserveMinTime(r.MinTime)
		out.ObserveMaxTime(r.MaxTime)
	}
	return
}

func (r *SyncSummary) Err() error {
	return multierr.Combine(r.syncErrors...)
}

func buildRecoverRange(tbl *glue.TableData, start, end time.Time) (*ScanRange, error) {
	if start.IsZero() {
		start = aws.TimeValue(tbl.CreateTime)
	}
	if end.IsZero() {
		end = time.Now()
	}
	start = GlueTableDaily.Truncate(start.UTC())
	end = GlueTableDaily.Truncate(end.UTC())
	if start.Equal(end) {
		end = GlueTableDaily.Next(start)
	}
	if start.Before(end) {
		return &ScanRange{
			Start: start,
			End:   end,
		}, nil
	}
	const layoutDaily = "2006-01-02"
	return nil, errors.Errorf("invalid time range %s %s", start.Format(layoutDaily), end.Format(layoutDaily))
}
