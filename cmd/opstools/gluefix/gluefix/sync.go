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

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
)

func runSync(ctx context.Context, sess *session.Session, log *zap.SugaredLogger) error {
	var matchPrefix string
	if optPrefix := *opts.LogTypePrefix; optPrefix != "" {
		matchPrefix = awsglue.GetTableName(optPrefix)
	}
	tasks := []*gluetasks.SyncDatabaseTables{
		{
			DatabaseName: awsglue.LogProcessingDatabaseName,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
		{
			DatabaseName:         awsglue.RuleErrorsDatabaseName,
			AfterTableCreateTime: true,
			DryRun:               *opts.DryRun,
			MatchPrefix:          matchPrefix,
			NumWorkers:           *opts.NumWorkers,
		},
		{
			DatabaseName:         awsglue.RuleMatchDatabaseName,
			AfterTableCreateTime: true,
			DryRun:               *opts.DryRun,
			MatchPrefix:          matchPrefix,
			NumWorkers:           *opts.NumWorkers,
		},
	}
	glueAPI := glue.New(sess)
	taskErrors := make([]error, len(tasks))
	wg := sync.WaitGroup{}
	wg.Add(len(tasks))
	for i, task := range tasks {
		task := task
		i := i
		go func() {
			defer wg.Done()
			taskErrors[i] = task.Run(ctx, glueAPI, log.Desugar())
		}()
	}
	wg.Wait()
	return multierr.Combine(taskErrors...)
}
