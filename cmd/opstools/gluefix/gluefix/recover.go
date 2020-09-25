package main

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
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
)

func runRecover(ctx context.Context, sess *session.Session, log *zap.SugaredLogger) error {
	var start, end time.Time
	if opt := *opts.RecoverEnd; opt != "" {
		tm, err := time.Parse(layoutDate, opt)
		if err != nil {
			log.Fatalf("could not parse 'end' flag %q (want YYYY-MM-DD): %s", opt, err)
		}
		end = tm
	}
	if opt := *opts.RecoverStart; opt != "" {
		tm, err := time.Parse(layoutDate, opt)
		if err != nil {
			log.Fatalf("could not parse 'start' flag %q (want YYYY-MM-DD): %s", opt, err)
		}
		start = tm
	}
	var matchPrefix string
	if optPrefix := *opts.LogTypePrefix; optPrefix != "" {
		matchPrefix = awsglue.GetTableName(optPrefix)
	}
	tasks := []gluetasks.RecoverDatabaseTables{
		{
			DatabaseName: awsglue.LogProcessingDatabaseName,
			Start:        start,
			End:          end,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
		{
			DatabaseName: awsglue.RuleErrorsDatabaseName,
			Start:        start,
			End:          end,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
		{
			DatabaseName: awsglue.RuleMatchDatabaseName,
			Start:        start,
			End:          end,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
	}
	glueAPI := glue.New(sess)
	s3API := s3.New(sess)
	taskErrors := make([]error, len(tasks))
	wg := sync.WaitGroup{}
	wg.Add(len(tasks))
	for i := range tasks {
		go func(i int) {
			task := &tasks[i]
			defer wg.Done()
			taskErrors[i] = task.Run(ctx, glueAPI, s3API, log.Desugar())
			log.Info("finished recovering %q: %v", task.DatabaseName, task.Stats)
		}(i)
	}
	wg.Wait()
	return multierr.Combine(taskErrors...)
}
