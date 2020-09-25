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
	"reflect"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

type SyncDatabaseTables struct {
	Start                time.Time
	MatchPrefix          string
	DatabaseName         string
	NumWorkers           int
	Stats                SyncStats
	DryRun               bool
	AfterTableCreateTime bool
}

func (s *SyncDatabaseTables) Run(ctx context.Context, api glueiface.GlueAPI, log *zap.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if log == nil {
		log = zap.NewNop()
	}
	log = log.With(
		zap.String("gluetask", "SyncDatabaseTables"),
		zap.String("db", s.DatabaseName),
	)
	log.Info("sync started")
	defer func(since time.Time) {
		log.Info("db sync finished", zap.Any("stats", &s.Stats), zap.Duration("duration", time.Since(since)))
	}(time.Now())
	tablePages := make(chan []*glue.TableData)
	var scanTablesErr error
	go func() {
		defer close(tablePages)
		input := glue.GetTablesInput{
			DatabaseName: &s.DatabaseName,
		}
		if s.MatchPrefix != "" {
			expr := "^" + regexp.QuoteMeta(s.MatchPrefix)
			input.Expression = &expr
		}
		log.Info("scanning for tables")
		scanTablesErr = api.GetTablesPagesWithContext(ctx, &input, func(page *glue.GetTablesOutput, _ bool) bool {
			log.Debug("table list found", zap.Int("numTables", len(page.TableList)))
			select {
			case tablePages <- page.TableList:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if scanTablesErr != nil {
			log.Error("table scan failed", zap.Error(scanTablesErr))
			cancel()
		}
	}()
	for page := range tablePages {
		tasks := make([]*SyncTablePartitions, len(page))
		taskErrors := make([]error, len(page))
		wg := sync.WaitGroup{}
		wg.Add(len(page))
		for i, tbl := range page {
			tbl := tbl
			task := &SyncTablePartitions{
				DatabaseName:         s.DatabaseName,
				AfterTableCreateTime: s.AfterTableCreateTime,
				TableName:            aws.StringValue(tbl.Name),
				NumWorkers:           s.NumWorkers,
				DryRun:               s.DryRun,
			}
			tasks[i] = task
			go func(i int) {
				defer wg.Done()
				err := task.syncTable(ctx, api, log, tbl)
				if err != nil {
					taskErrors[i] = err
				}
			}(i)
		}
		wg.Wait()

		var err error
		for i, task := range tasks {
			err = multierr.Append(err, taskErrors[i])
			s.Stats.merge(&task.Stats)
		}
		if err != nil {
			log.Error("failed to sync table", zap.Error(err))
			cancel()
			return err
		}
	}
	return nil
}

type SyncTablePartitions struct {
	DatabaseName         string
	TableName            string
	NumWorkers           int
	NextToken            string
	Stats                SyncStats
	AfterTableCreateTime bool
	DryRun               bool
}

func (s *SyncTablePartitions) Run(ctx context.Context, api glueiface.GlueAPI, log *zap.Logger) error {
	if log == nil {
		log = zap.NewNop()
	}
	log = log.With(
		zap.String("gluetask", "SyncTablePartitions"),
		zap.String("db", s.DatabaseName),
		zap.String("table", s.TableName),
	)

	defer func(since time.Time) {
		log.Info("table sync finished", zap.Duration("duration", time.Since(since)), zap.Any("stats", &s.Stats))
	}(time.Now())

	tbl, err := findTable(ctx, api, s.DatabaseName, s.TableName)
	if err != nil {
		log.Error("table not found", zap.Error(err))
		return err
	}
	return s.syncTable(ctx, api, log, tbl)
}

func (s *SyncTablePartitions) syncTable(ctx context.Context, api glueiface.GlueAPI, log *zap.Logger, tbl *glue.TableData) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pageQueue := make(chan *glue.GetPartitionsOutput)
	var scanError error
	go func() {
		defer close(pageQueue)
		input := glue.GetPartitionsInput{
			DatabaseName: tbl.DatabaseName,
			CatalogId:    tbl.CatalogId,
			TableName:    tbl.Name,
		}
		if s.AfterTableCreateTime && tbl.CreateTime != nil {
			expr := daily.PartitionsAfter(*tbl.CreateTime)
			input.Expression = &expr
		}
		if s.NextToken != "" {
			input.NextToken = &s.NextToken
		}
		log.Info("scanning partitions")
		scanError = api.GetPartitionsPagesWithContext(ctx, &input, func(page *glue.GetPartitionsOutput, _ bool) bool {
			log.Debug("partitions found", zap.Int("numPartitions", len(page.Partitions)))
			select {
			case pageQueue <- page:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if scanError != nil {
			log.Error("partition scan failed", zap.Error(scanError))
			// abort early
			cancel()
		}
	}()

	for page := range pageQueue {
		s.Stats.NumPages++
		var tasks []partitionUpdate
		for _, p := range page.Partitions {
			tm, err := awsglue.PartitionTimeFromValues(p.Values)
			if err != nil {
				log.Warn("invalid partition", zap.Strings("values", aws.StringValueSlice(p.Values)), zap.Error(err))
				return errors.Wrapf(err, "failed to sync %s.%s partitions", s.DatabaseName, s.TableName)
			}
			s.Stats.observePartition(tm)
			if isSynced(tbl, p) {
				continue
			}
			s.Stats.NumDiff++
			if s.DryRun {
				log.Debug("skipping partition update", zap.String("reason", "dryRun"), zap.String("partition", tm.Format(time.RFC3339)))
				continue
			}
			tasks = append(tasks, partitionUpdate{
				Partition: p,
				Table:     tbl,
				Time:      tm,
			})
		}
		if len(tasks) == 0 {
			continue
		}
		queue := make(chan partitionUpdate)
		go func() {
			// signals workers to exit
			defer close(queue)
			for _, task := range tasks {
				select {
				case queue <- task:
					log.Info("updating partition", zap.Stringer("partitionTime", task.Time))
				case <-ctx.Done():
					return
				}
			}
		}()
		// Process updates in parallel
		numSynced, err := processPartitionUpdates(ctx, api, queue, s.NumWorkers)
		s.Stats.NumSynced += int(numSynced)
		if err := multierr.Append(ctx.Err(), err); err != nil {
			return err
		}
		// Only update next token if all partitions in page were processed
		s.NextToken = aws.StringValue(page.NextToken)
	}
	return scanError
}

func findTable(ctx context.Context, api glueiface.GlueAPI, dbName, tblName string) (*glue.TableData, error) {
	reply, err := api.GetTableWithContext(ctx, &glue.GetTableInput{
		DatabaseName: &dbName,
		Name:         &tblName,
	})
	if err != nil {
		return nil, err
	}
	return reply.Table, nil
}
func isSynced(tbl *glue.TableData, p *glue.Partition) bool {
	want := tbl.StorageDescriptor.Columns
	have := p.StorageDescriptor.Columns
	//s.Logger.Debug("diff", zap.Any("colsWant", want), zap.Any("colsHave", have))
	if len(want) != len(have) {
		return false
	}
	return reflect.DeepEqual(want, have)
}

type partitionUpdate struct {
	Partition *glue.Partition
	Table     *glue.TableData
	Time      time.Time
}

func processPartitionUpdates(ctx context.Context, api glueiface.GlueAPI, queue <-chan partitionUpdate, numWorkers int) (int64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if numWorkers < 1 {
		numWorkers = 1
	}
	var numSynced int64
	syncErrors := make([]error, numWorkers)
	wg := sync.WaitGroup{}
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		i := i
		go func() {
			defer wg.Done()
			for task := range queue {
				err := syncPartition(ctx, api, task.Table, task.Partition)
				switch err {
				case nil:
					atomic.AddInt64(&numSynced, 1)
				case context.Canceled, context.DeadlineExceeded:
					return
				default:
					syncErrors[i] = err
					// abort early
					cancel()
					return
				}
			}
		}()
	}
	wg.Wait()
	return numSynced, multierr.Combine(syncErrors...)
}

func syncPartition(ctx context.Context, api glueiface.GlueAPI, tbl *glue.TableData, p *glue.Partition) error {
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
	_, err := api.UpdatePartitionWithContext(ctx, &input)
	return err
}

type SyncStats struct {
	NumPages         int
	NumPartitions    int
	NumDiff          int
	NumSynced        int
	MinTime, MaxTime time.Time
}

func (s *SyncStats) merge(other *SyncStats) {
	s.NumSynced += other.NumSynced
	s.NumPages += other.NumPages
	s.NumPartitions += other.NumPartitions
	s.NumPartitions += other.NumPartitions
	s.NumDiff += other.NumDiff
	s.observeMinTime(other.MinTime)
	s.observeMaxTime(other.MaxTime)
}

func (s *SyncStats) observePartition(tm time.Time) {
	s.NumPartitions++
	s.observeMinTime(tm)
	s.observeMaxTime(tm)
}

func (s *SyncStats) observeMinTime(tm time.Time) {
	if s.MinTime.IsZero() || s.MinTime.After(tm) {
		s.MinTime = tm
	}
}
func (s *SyncStats) observeMaxTime(tm time.Time) {
	if s.MaxTime.Before(tm) {
		s.MaxTime = tm
	}
}
