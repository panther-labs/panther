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
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

const (
	daily  = awsglue.GlueTableDaily
	hourly = awsglue.GlueTableHourly
)

type RecoverDatabaseTables struct {
	// DatabaseName scans this Glue database for missing partitions
	DatabaseName string
	// MatchPrefix will match tables whose name begins with this prefix
	MatchPrefix string
	// Start sets the start of the scan range
	Start time.Time
	// End sets the end of the scan range
	End time.Time
	// NumWorkers sets the number of parallel scans to run on each table
	NumWorkers int
	// DryRun is a flag to not modify any partitions
	DryRun bool
	// Stats holds the stats for all tables recovered
	Stats RecoverStats
}

// Run executes the recovery
func (r *RecoverDatabaseTables) Run(ctx context.Context, glueAPI glueiface.GlueAPI, s3API s3iface.S3API, log *zap.Logger) error {
	if log == nil {
		log = zap.NewNop()
	}
	log = log.Named("RecoverDatabase").With(
		zap.String("database", r.DatabaseName),
	)
	group, ctx := errgroup.WithContext(ctx)
	tables := make(chan []*glue.TableData)
	group.Go(func() error {
		defer close(tables)
		log.Info("scanning for tables")
		input := glue.GetTablesInput{
			DatabaseName: &r.DatabaseName,
		}
		if r.MatchPrefix != "" {
			expr := r.MatchPrefix + "*"
			input.Expression = &expr
		}
		err := glueAPI.GetTablesPagesWithContext(ctx, &input, func(page *glue.GetTablesOutput, _ bool) bool {
			select {
			case tables <- page.TableList:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if err != nil {
			log.Error("failed to scan tables", zap.Error(err))
		}
		return err
	})
	group.Go(func() error {
		for page := range tables {
			tasks := make([]*RecoverTablePartitions, len(page))
			childGroup, ctx := errgroup.WithContext(ctx)
			for i, tbl := range page {
				i, tbl := i, tbl
				start := r.Start
				if start.IsZero() {
					start = *tbl.CreateTime
				}
				end := r.End
				if end.IsZero() {
					end = time.Now()
				}
				task := &RecoverTablePartitions{
					Start:        r.Start,
					End:          r.End,
					DatabaseName: r.DatabaseName,
					TableName:    aws.StringValue(tbl.Name),
					NumWorkers:   r.NumWorkers,
					DryRun:       r.DryRun,
				}
				tasks[i] = task
				childGroup.Go(func() error {
					log := log.With(zap.String("table", task.TableName))
					return task.recoverTable(ctx, glueAPI, s3API, log, tbl)
				})
			}
			err := childGroup.Wait()
			for _, task := range tasks {
				r.Stats.merge(task.Stats)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	return group.Wait()
}

// RecoverTablePartitions scans a date range to recover missing partitions
type RecoverTablePartitions struct {
	DatabaseName string
	TableName    string
	NumWorkers   int
	DryRun       bool
	Start        time.Time
	End          time.Time
	LastDate     time.Time
	Stats        RecoverStats
}

func (r *RecoverTablePartitions) Run(ctx context.Context, apiGlue glueiface.GlueAPI, apiS3 s3iface.S3API, log *zap.Logger) error {
	tbl, err := findTable(ctx, apiGlue, r.DatabaseName, r.TableName)
	if log == nil {
		log = zap.NewNop()
	}
	log = log.Named("RecoverTablePartitions").With(
		zap.String("database", r.DatabaseName),
		zap.String("table", r.TableName),
	)
	if err != nil {
		log.Error("table not found", zap.Error(err))
		return err
	}
	return r.recoverTable(ctx, apiGlue, apiS3, log, tbl)
}

func (r *RecoverTablePartitions) recoverTable(ctx context.Context, glueAPI glueiface.GlueAPI, s3API s3iface.S3API,

	log *zap.Logger, tbl *glue.TableData) (err error) {

	start := r.LastDate
	if start.IsZero() {
		start = r.Start
	}
	start, end, err := buildRecoverRange(tbl, start, r.End)
	if err != nil {
		return err
	}
	log.Info("starting recovery", zap.Stringer("start", start), zap.Stringer("end", end))
	defer func(since time.Time) {
		delta := time.Since(since)
		if err != nil {
			log.Error("recover failed", zap.Error(err), zap.Duration("duration", delta), zap.Any("stats", &r.Stats))
		} else {
			log.Info("recover finished", zap.Duration("duration", delta), zap.Any("stats", &r.Stats))
		}
	}(time.Now())

	partitions := make(map[time.Time]bool)
	expr := hourly.PartitionsBetween(start, end)
	input := glue.GetPartitionsInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		TableName:    tbl.Name,
		Expression:   &expr,
	}
	log.Info("scanning for partitions")
	err = glueAPI.GetPartitionsPagesWithContext(ctx, &input, func(page *glue.GetPartitionsOutput, _ bool) bool {
		for _, p := range page.Partitions {
			tm, err := awsglue.PartitionTimeFromValues(p.Values)
			if err != nil {
				continue
			}
			partitions[tm] = true
		}
		return true
	})
	if err != nil {
		log.Error("partition scan failed", zap.Error(err))
		return err
	}
	log.Info("partitions scanned", zap.Int("numPartitions", len(partitions)))
	tasks := make(chan recoverTask)
	go func() {
		defer close(tasks)
		for tm := start; tm.Before(end); tm = daily.Next(tm) {
			select {
			case tasks <- recoverTask{
				table:      tbl,
				partitions: partitions,
				date:       tm,
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
	table      *glue.TableData
	partitions map[time.Time]bool
	date       time.Time
}

func (r *RecoverTablePartitions) processRecoverTasks(ctx context.Context, tasks <-chan recoverTask, w recoverWorker, numWorkers int) error {
	group, ctx := errgroup.WithContext(ctx)
	if numWorkers < 1 {
		numWorkers = 1
	}
	workers := make([]recoverWorker, numWorkers)
	for i := range workers {
		workers[i] = w
	}
	for i := range workers {
		w := &workers[i]
		group.Go(func() error {
			for task := range tasks {
				err := w.recoverPartitionAt(ctx, task.table, task.date, task.partitions)
				if err != nil {
					w.err = err
					return err
				}
				// Since dates are always delivered in ascending order no need to check the current value
				w.lastDateProcessed = task.date
			}
			return nil
		})
	}
	err := group.Wait()
	for i := range workers {
		w := &workers[i]
		r.Stats.merge(w.stats)
		if r.LastDate.Before(w.lastDateProcessed) {
			r.LastDate = w.lastDateProcessed
		}
	}
	return err
}

type recoverWorker struct {
	glue              glueiface.GlueAPI
	dryRun            bool
	s3                s3iface.S3API
	log               *zap.Logger
	lastDateProcessed time.Time
	stats             RecoverStats
	err               error
}

func (w *recoverWorker) recoverPartitionAt(ctx context.Context, tbl *glue.TableData, tm time.Time, partitions map[time.Time]bool) error {
	start := daily.Truncate(tm)
	end := daily.Next(start)
	batch := &glue.BatchCreatePartitionInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		TableName:    tbl.Name,
	}
	// Iterate over each hour in the day
	for tm := start; tm.Before(end); tm = hourly.Next(tm) {
		// Skip an hour if a partition already exists
		if _, ok := partitions[tm]; ok {
			w.log.Debug("partition already exists", zap.String("time", tm.Format("2006-01-02 15:04")))
			continue
		}
		w.log.Info("scanning partition", zap.String("time", tm.Format("2006-01-02 15:04")))
		// Check to see if there are data for this partition in S3
		s3Location, err := w.findS3PartitionAt(ctx, tbl, tm)
		if err != nil {
			// No data found, skip to the next hour
			if errors.Is(err, errS3ObjectNotFound) {
				w.log.Debug("no partition data found", zap.String("time", tm.Format("2006-01-02 15:04")))
				w.stats.NumS3Miss++
				continue
			}
			return err
		}
		w.log.Debug("found recoverable partition",
			zap.String("location", s3Location),
			zap.String("time", tm.Format("2006-01-02 15:04")),
		)
		w.stats.NumS3Hit++
		// We found a partition to be recovered
		desc := *tbl.StorageDescriptor
		desc.Location = aws.String(s3Location)
		batch.PartitionInputList = append(batch.PartitionInputList, &glue.PartitionInput{
			StorageDescriptor: &desc,
			Values:            hourly.PartitionValuesFromTime(tm),
		})
	}
	batchSize := len(batch.PartitionInputList)
	if batchSize == 0 {
		return nil
	}
	if w.dryRun {
		w.log.Info("dryrun, skipping partition creation", zap.Int("numFound", batchSize))
		return nil
	}
	// Recover all partitions with a single batch API call
	reply, err := w.glue.BatchCreatePartitionWithContext(ctx, batch)
	if err != nil {
		w.stats.NumFailed += batchSize
		return errors.Wrapf(err, "failed to recover %d partitions", batchSize)
	}
	w.stats.NumRecovered += batchSize
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
		w.stats.NumRecovered--
		if e.ErrorDetail == nil {
			continue
		}
		code := aws.StringValue(e.ErrorDetail.ErrorCode)
		if code == glue.ErrCodeAlreadyExistsException {
			continue
		}
		w.stats.NumFailed++
		message := aws.StringValue(e.ErrorDetail.ErrorMessage)
		tm, _ := awsglue.PartitionTimeFromValues(e.PartitionValues)
		reason := errors.Errorf("failed to recover Glue partition at %s", tm)
		awsErr := awserr.New(code, message, reason)
		err = multierr.Append(err, awsErr)
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
	objPrefix := path.Join(tblPrefix, bin.PartitionPathS3(tm))
	objPrefix = objPrefix + "/"
	// We use as small number of max keys to avoid multiple calls in case there are empty objects
	const maxKeys = 100
	listObjectsInput := s3.ListObjectsV2Input{
		Bucket:  &bucket,
		Prefix:  &objPrefix,
		MaxKeys: aws.Int64(maxKeys),
	}
	hasData := false
	onPage := func(page *s3.ListObjectsV2Output, isLast bool) bool {
		for _, obj := range page.Contents {
			if aws.Int64Value(obj.Size) > 0 {
				hasData = true
				return false // Stop S3 scan iterator
			}
		}
		return true // All objects where empty, keep looking
	}
	if err := w.s3.ListObjectsV2PagesWithContext(ctx, &listObjectsInput, onPage); err != nil {
		return "", err
	}
	if !hasData {
		// We use the well-known error to communicate the not found case
		return "", errors.Wrapf(errS3ObjectNotFound, "no partition data for %q at %s", aws.StringValue(tbl.Name), tm)
	}
	return fmt.Sprintf("s3://%s/%s", bucket, objPrefix), nil
}

func buildRecoverRange(tbl *glue.TableData, start, end time.Time) (time.Time, time.Time, error) {
	createTime := aws.TimeValue(tbl.CreateTime)
	maxTime := daily.Next(time.Now())
	dbName := aws.StringValue(tbl.DatabaseName)
	if start.IsZero() {
		start = createTime
	}
	if end.IsZero() {
		end = maxTime
	}
	switch dbName {
	case pantherdb.LogProcessingDatabase:
		// Do not cap dates for log tables.
		// Log tables are partitioned by event time and that could be in the past or future.
	default:
		if start.Before(createTime) {
			start = createTime
		}
		if end.After(maxTime) {
			end = maxTime
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

func (s *RecoverStats) merge(others ...RecoverStats) {
	for _, other := range others {
		s.NumRecovered += other.NumRecovered
		s.NumS3Hit += other.NumS3Hit
		s.NumS3Miss += other.NumS3Miss
		s.NumProcessed += other.NumProcessed
		s.NumFailed += other.NumFailed
	}
}
