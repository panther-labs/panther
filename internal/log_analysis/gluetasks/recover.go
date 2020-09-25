package gluetasks

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

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

const (
	daily  = awsglue.GlueTableDaily
	hourly = awsglue.GlueTableHourly
)

type RecoverDatabaseTables struct {
	MatchPrefix  string
	DatabaseName string
	Start        time.Time
	End          time.Time
	NumWorkers   int
	DryRun       bool
	LastDate     time.Time
	Stats        RecoverStats
}

func (r *RecoverDatabaseTables) Run(ctx context.Context, glueAPI glueiface.GlueAPI, s3API s3iface.S3API, log *zap.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tables := make(chan []*glue.TableData)
	var scanTablesErr error
	go func() {
		defer close(tables)
		input := glue.GetTablesInput{
			DatabaseName: &r.DatabaseName,
		}
		if r.MatchPrefix != "" {
			expr := "^" + regexp.QuoteMeta(r.MatchPrefix)
			input.Expression = &expr
		}
		scanTablesErr = glueAPI.GetTablesPagesWithContext(ctx, &input, func(page *glue.GetTablesOutput, _ bool) bool {
			select {
			case tables <- page.TableList:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if scanTablesErr != nil {
			cancel()
		}
	}()
	for page := range tables {
		tasks := make([]RecoverTablePartitions, len(page))
		taskErrors := make([]error, len(page))
		wg := sync.WaitGroup{}
		wg.Add(len(page))
		for i, tbl := range page {
			tbl := tbl
			i := i
			task := &tasks[i]
			start := r.Start
			if start.IsZero() {
				start = *tbl.CreateTime
			}
			end := r.End
			if end.IsZero() {
				end = time.Now()
			}
			*task = RecoverTablePartitions{
				Start:        r.Start,
				End:          r.End,
				DatabaseName: r.DatabaseName,
				TableName:    aws.StringValue(tbl.Name),
				NumWorkers:   r.NumWorkers,
				DryRun:       r.DryRun,
			}
			go func() {
				defer wg.Done()
				err := task.recoverTable(ctx, glueAPI, s3API, log, tbl)
				if err != nil {
					taskErrors[i] = err
				}
			}()
		}
		wg.Wait()

		var err error
		for i, task := range tasks {
			err = multierr.Append(err, taskErrors[i])
			r.Stats.merge(&task.Status)
		}
		if err != nil {
			cancel()
			return err
		}
	}
	return nil
}

type RecoverTablePartitions struct {
	DatabaseName string
	TableName    string
	NumWorkers   int
	DryRun       bool
	Start        time.Time
	End          time.Time
	LastDate     time.Time
	Status       RecoverStats
}

func (r *RecoverTablePartitions) Run(ctx context.Context, apiGlue glueiface.GlueAPI, apiS3 s3iface.S3API, log *zap.Logger) error {
	tbl, err := findTable(ctx, apiGlue, r.DatabaseName, r.TableName)
	if err != nil {
		return err
	}
	return r.recoverTable(ctx, apiGlue, apiS3, log, tbl)
}

func (r *RecoverTablePartitions) recoverTable(ctx context.Context,
	glueAPI glueiface.GlueAPI, s3API s3iface.S3API, log *zap.Logger, tbl *glue.TableData) error {

	start := r.LastDate
	if start.IsZero() {
		start = r.Start
	}
	start, end, err := buildRecoverRange(tbl, start, r.End)
	if err != nil {
		return err
	}
	if log == nil {
		log = zap.NewNop()
	}
	log = log.With(
		zap.String("gluetask", "recover"),
		zap.String("database", r.DatabaseName),
		zap.String("table", r.TableName),
		zap.Stringer("start", start),
		zap.Stringer("end", end),
	)
	tasks := make(chan recoverTask)
	go func() {
		defer close(tasks)
		for tm := start; tm.Before(end); tm = daily.Next(tm) {
			select {
			case tasks <- recoverTask{
				table: tbl,
				date:  tm,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return r.processRecoverTasks(ctx, tasks, recoverWorker{
		glue:   glueAPI,
		dryRun: r.DryRun,
		s3:     s3API,
		log:    log,
	}, r.NumWorkers)
}

type recoverTask struct {
	table *glue.TableData
	date  time.Time
}

func (r *RecoverTablePartitions) processRecoverTasks(ctx context.Context, tasks <-chan recoverTask, w recoverWorker, numWorkers int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if numWorkers < 1 {
		numWorkers = 1
	}
	wg := sync.WaitGroup{}
	workers := make([]recoverWorker, numWorkers)
	wg.Add(numWorkers)
	for i := range workers {
		workers[i] = w
	}
	for i := range workers {
		w := &workers[i]
		go func() {
			defer wg.Done()
			for task := range tasks {
				err := w.recoverPartitionAt(ctx, task.table, task.date)
				switch err {
				case nil:
					w.lastDateProcessed = task.date
				case context.DeadlineExceeded, context.Canceled:
					return
				default:
					w.err = err
					cancel()
					return
				}
			}
		}()
	}
	wg.Wait()
	var err error
	for _, w := range workers {
		r.Status.merge(&w.status)
		if r.LastDate.Before(w.lastDateProcessed) {
			r.LastDate = w.lastDateProcessed
		}
		err = multierr.Append(err, w.err)
	}
	return err
}

type recoverWorker struct {
	glue              glueiface.GlueAPI
	dryRun            bool
	s3                s3iface.S3API
	log               *zap.Logger
	lastDateProcessed time.Time
	status            RecoverStats
	err               error
}

func (w *recoverWorker) recoverPartitionAt(ctx context.Context, tbl *glue.TableData, tm time.Time) error {
	partitions, err := w.findGluePartitionsAt(ctx, tbl, tm)
	w.status.NumProcessed += len(partitions)
	if err != nil {
		return err
	}
	if len(partitions) == 24 {
		return nil
	}
	start := daily.Truncate(tm)
	end := daily.Next(tm)
	batch := &glue.BatchCreatePartitionInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		TableName:    tbl.Name,
	}
	// Iterate over each hour in the day
	for tm := start; tm.Before(end); tm = hourly.Next(tm) {
		// Skip an hour if a partition already exists
		if _, ok := partitions[tm]; ok {
			continue
		}
		// Check to see if there are data for this partition in S3
		location, err := w.findS3PartitionAt(ctx, tbl, tm)
		if err != nil {
			// No data found, skip to the next hour
			if errors.Is(err, errS3ObjectNotFound) {
				w.status.NumS3Miss++
				continue
			}
			return err
		}
		w.status.NumS3Hit++
		// We found a partition to be recovered
		desc := *tbl.StorageDescriptor
		desc.Location = aws.String(location)
		batch.PartitionInputList = append(batch.PartitionInputList, &glue.PartitionInput{
			StorageDescriptor: &desc,
			Values:            hourly.PartitionValuesFromTime(tm),
		})
	}
	batchSize := len(batch.PartitionInputList)
	if w.dryRun {
		w.log.Info("dryrun, skipping partition creation", zap.Int("numFound", batchSize))
		return nil
	}
	// RecoverTable all partitions with a single API call
	reply, err := w.glue.BatchCreatePartitionWithContext(ctx, batch)
	if err != nil {
		w.status.NumFailed += batchSize
		return errors.Wrapf(err, "failed to recover %d partitions", batchSize)
	}
	w.status.NumRecovered += batchSize
	// Collect errors, ignoring AlreadyExists
	if err := w.collectErrors(reply.Errors); err != nil {
		return err
	}
	return nil
}

func (w *recoverWorker) collectErrors(replyErrors []*glue.PartitionError) (err error) {
	for _, e := range replyErrors {
		if e == nil {
			continue
		}
		w.status.NumRecovered--
		if e.ErrorDetail == nil {
			continue
		}
		code := aws.StringValue(e.ErrorDetail.ErrorCode)
		if code == glue.ErrCodeAlreadyExistsException {
			continue
		}
		w.status.NumFailed++
		message := aws.StringValue(e.ErrorDetail.ErrorMessage)
		tm, _ := awsglue.PartitionTimeFromValues(e.PartitionValues)
		// Using fmt.Errorf to not add stack (this is a helper)
		reason := fmt.Errorf("failed to recover Glue partition at %s", tm)
		awsErr := awserr.New(code, message, reason)

		err = multierr.Append(err, errors.WithStack(awsErr))
	}
	return
}

var errS3ObjectNotFound = goerr.New("s3 object not found")

func (w *recoverWorker) findS3PartitionAt(ctx context.Context, tbl *glue.TableData, tm time.Time) (string, error) {
	bin, err := awsglue.TimebinFromTable(tbl)
	if err != nil {
		return "", err
	}
	bucket, tblPrefix, err := awsglue.ParseS3URL(*tbl.StorageDescriptor.Location)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to parse S3 path for table %q", aws.StringValue(tbl.Name))
	}
	objPrefix := path.Join(tblPrefix, bin.PartitionS3PathFromTime(tm)) + "/"
	listObjectsInput := s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(objPrefix),
		MaxKeys: aws.Int64(10),
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
	if err := w.s3.ListObjectsV2PagesWithContext(ctx, &listObjectsInput, onPage); err != nil {
		return "", err
	}
	if !hasData {
		return "", errors.Wrapf(errS3ObjectNotFound, "no partition data for %q at %s", aws.StringValue(tbl.Name), tm)
	}
	return fmt.Sprintf("s3://%s/%s", bucket, objPrefix), nil
}

// nolint:lll
func (w *recoverWorker) findGluePartitionsAt(ctx context.Context, tbl *glue.TableData, tm time.Time) (map[time.Time]*glue.Partition, error) {
	tm = tm.UTC()
	filter := fmt.Sprintf(`year = %d AND month = %d AND day = %d`, tm.Year(), tm.Month(), tm.Day())
	reply, err := w.glue.GetPartitionsWithContext(ctx, &glue.GetPartitionsInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		TableName:    tbl.Name,
		Expression:   &filter,
	})
	if err != nil {
		return nil, err
	}
	partitions := make(map[time.Time]*glue.Partition, 24)
	for _, p := range reply.Partitions {
		tm, err := awsglue.PartitionTimeFromValues(p.Values)
		if err != nil {
			return partitions, err
		}
		partitions[tm] = p
	}
	return partitions, nil
}

func buildRecoverRange(tbl *glue.TableData, start, end time.Time) (time.Time, time.Time, error) {
	createTime := aws.TimeValue(tbl.CreateTime)
	dbName := aws.StringValue(tbl.DatabaseName)
	if start.IsZero() {
		start = createTime
	}
	if end.IsZero() {
		end = time.Now()
	}
	if dbName != awsglue.LogProcessingDatabaseName {
		if start.Before(createTime) {
			start = createTime
		}
		if now := time.Now(); end.After(now) {
			end = now
		}
	}
	start = daily.Truncate(start.UTC())
	end = daily.Truncate(end.UTC())
	if start.Equal(end) {
		end = daily.Next(start)
	}
	if start.Before(end) {
		return start, end, nil
	}
	const layoutDaily = "2006-01-02"
	return time.Time{}, time.Time{}, errors.Errorf("invalid time range %s %s", start.Format(layoutDaily), end.Format(layoutDaily))
}

type RecoverStats struct {
	NumRecovered int
	NumS3Hit     int
	NumFailed    int
	NumS3Miss    int
	NumProcessed int
}

func (s *RecoverStats) merge(other *RecoverStats) {
	s.NumRecovered += other.NumRecovered
	s.NumS3Hit += other.NumS3Hit
	s.NumS3Miss += other.NumS3Miss
	s.NumProcessed += other.NumProcessed
	s.NumFailed += other.NumFailed
}
