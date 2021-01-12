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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

type SyncDatabaseTables struct {
	Start        time.Time
	MatchPrefix  string
	DatabaseName string
	NumWorkers   int
	Stats        SyncStats
	DryRun       bool
}

func (s *SyncDatabaseTables) Run(ctx context.Context, api glueiface.GlueAPI, log *zap.Logger) error {
	group, ctx := errgroup.WithContext(ctx)
	if log == nil {
		log = zap.NewNop()
	}
	log = log.Named("SyncDatabaseTables").With(zap.String("database", s.DatabaseName))
	log.Info("sync started")
	defer func(since time.Time) {
		log.Info("db sync finished", zap.Any("stats", &s.Stats), zap.Duration("duration", time.Since(since)))
	}(time.Now())
	tablePages := make(chan []*glue.TableData)
	group.Go(func() error {
		defer close(tablePages)
		input := glue.GetTablesInput{
			DatabaseName: &s.DatabaseName,
		}
		if s.MatchPrefix != "" {
			expr := s.MatchPrefix + "*"
			input.Expression = &expr
		}
		log.Info("scanning for tables")
		err := api.GetTablesPagesWithContext(ctx, &input, func(page *glue.GetTablesOutput, _ bool) bool {
			log.Debug("table list found", zap.Int("numTables", len(page.TableList)))
			select {
			case tablePages <- page.TableList:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if err != nil {
			log.Error("table scan failed", zap.Error(err))
		}
		return err
	})
	group.Go(func() error {
		for page := range tablePages {
			tasks := make([]*SyncTablePartitions, len(page))
			childGroup, ctx := errgroup.WithContext(ctx)
			for i, tbl := range page {
				i, tbl := i, tbl
				task := &SyncTablePartitions{
					DatabaseName: s.DatabaseName,
					TableName:    aws.StringValue(tbl.Name),
					NumWorkers:   s.NumWorkers,
					DryRun:       s.DryRun,
				}
				tasks[i] = task
				childGroup.Go(func() error {
					log := log.With(zap.String("table", task.TableName))
					return task.syncTable(ctx, api, log, tbl)
				})
			}
			err := childGroup.Wait()
			for _, task := range tasks {
				s.Stats.merge(&task.Stats)
			}
			if err != nil {
				log.Error("failed to sync db tables", zap.Error(err))
				return err
			}
		}
		return nil
	})
	return group.Wait()
}

type SyncTablePartitions struct {
	DatabaseName string
	TableName    string
	NumWorkers   int
	NextToken    string
	Stats        SyncStats
	DryRun       bool
}

func (s *SyncTablePartitions) Run(ctx context.Context, api glueiface.GlueAPI, log *zap.Logger) error {
	log = s.buildLogger(log).Named("SyncTablePartitions").With(
		zap.String("database", s.DatabaseName),
	)
	defer func(since time.Time) {
		log.Info("table sync finished",
			zap.Duration("duration", time.Since(since)),
			zap.Any("stats", &s.Stats),
		)
	}(time.Now())

	tbl, err := findTable(ctx, api, s.DatabaseName, s.TableName)
	if err != nil {
		log.Error("table not found",
			zap.String("database", s.DatabaseName),
			zap.String("table", s.TableName),
			zap.Error(err))
		return err
	}
	return s.syncTable(ctx, api, log, tbl)
}

func (s *SyncTablePartitions) syncTable(ctx context.Context, api glueiface.GlueAPI, log *zap.Logger, tbl *glue.TableData) error {
	group, ctx := errgroup.WithContext(ctx)
	pageQueue := make(chan *glue.GetPartitionsOutput)
	group.Go(func() error {
		defer close(pageQueue)
		input := glue.GetPartitionsInput{
			DatabaseName: tbl.DatabaseName,
			CatalogId:    tbl.CatalogId,
			TableName:    tbl.Name,
		}
		if s.NextToken != "" {
			input.NextToken = &s.NextToken
		}
		log.Info("scanning partitions")
		err := api.GetPartitionsPagesWithContext(ctx, &input, func(page *glue.GetPartitionsOutput, _ bool) bool {
			log.Debug("partitions found", zap.Int("numPartitions", len(page.Partitions)))
			select {
			case pageQueue <- page:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if err != nil {
			log.Error("partition scan failed", zap.Error(err))
		}
		return err
	})
	group.Go(func() error {
		for page := range pageQueue {
			s.Stats.NumPages++
			var tasks []partitionUpdate
			for _, p := range page.Partitions {
				tm, err := awsglue.PartitionTimeFromValues(p.Values)
				if err != nil {
					log.Warn("invalid partition values", zap.Strings("values", aws.StringValueSlice(p.Values)), zap.Error(err))
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

			// Process updates in parallel
			log.Info("updating partitions", zap.Int("numPartitions", len(tasks)))
			numSynced, err := processPartitionUpdates(ctx, api, tasks, s.NumWorkers)
			s.Stats.NumSynced += int(numSynced)
			if err != nil {
				return err
			}
			// Only update next token if all partitions in page were processed
			s.NextToken = aws.StringValue(page.NextToken)
		}
		return nil
	})
	return group.Wait()
}

func (s *SyncTablePartitions) buildLogger(log *zap.Logger) *zap.Logger {
	return log.With(zap.String("table", s.TableName))
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
	// FIXME: remove this in the future, this is for backward compatibility (we used to have 4 partitions, we now have 5)
	if len(p.Values) != 5 {
		return false
	}
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

func processPartitionUpdates(ctx context.Context, api glueiface.GlueAPI, tasks []partitionUpdate, numWorkers int) (int64, error) {
	group, ctx := errgroup.WithContext(ctx)
	queue := make(chan partitionUpdate)
	group.Go(func() error {
		// signals workers to exit
		defer close(queue)
		for _, task := range tasks {
			select {
			case queue <- task:
			case <-ctx.Done():
				break
			}
		}
		return nil
	})
	if numWorkers < 1 {
		numWorkers = 1
	}
	var numSynced int64
	for i := 0; i < numWorkers; i++ {
		group.Go(func() error {
			for task := range queue {
				err := syncPartition(ctx, api, task.Table, task.Partition)
				switch err {
				case nil:
					atomic.AddInt64(&numSynced, 1)
					continue
				case context.Canceled, context.DeadlineExceeded:
					return nil
				default:
					return err
				}
			}
			return nil
		})
	}
	return numSynced, group.Wait()
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
	// FIXME: remove this in the future, this is for backward compatibility (we used to have 4 partitions, we now have 5)
	if len(p.Values) < 5 {
		partitionTime, err := awsglue.PartitionTimeFromValues(p.Values)
		if err != nil {
			return err
		}
		updatedPartitionValues := make([]*string, 5)
		copy(updatedPartitionValues, p.Values)
		updatedPartitionValues[4] = aws.String(strconv.Itoa(int(partitionTime.Unix())))
		input.PartitionInput.Values = updatedPartitionValues
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
