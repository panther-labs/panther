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
	"flag"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

var (
	version string // we expect this to be set by the build tool as `-X main.version=<some version>`
)

func main() {
	opstools.SetUsage("scans S3 for missing AWS Glue partitions and recovers them (Panther version %s)", version)
	opts := struct {
		MasterStack    *string
		End            *string
		Start          *string
		DryRun         *bool
		Debug          *bool
		Region         *string
		NumWorkers     *int
		MaxConnections *int
		MaxRetries     *int
		Prefix         *string
	}{
		MasterStack: flag.String("master-stack", "",
			"if set, this is the name of the Panther master stack used to deploy, if not set the deployment is assumed from source"),
		Start:          flag.String("start", "", "Recover partitions after this date YYYY-MM-DD"),
		End:            flag.String("end", "", "Recover partitions until this date YYYY-MM-DD"),
		DryRun:         flag.Bool("dry-run", false, "Scan for missing partitions without without applying any changes"),
		Debug:          flag.Bool("debug", false, "Enable additional logging"),
		Region:         flag.String("region", "", "Set the AWS region to run on"),
		MaxRetries:     flag.Int("max-retries", 12, "Max retries for AWS requests"),
		MaxConnections: flag.Int("max-connections", 100, "Max number of connections to AWS"),
		NumWorkers:     flag.Int("workers", 8, "Number of parallel workers for each table"),
		Prefix:         flag.String("prefix", "", "A prefix to filter log type names"),
	}
	flag.Parse()

	log := opstools.MustBuildLogger(*opts.Debug)
	var start, end time.Time
	if opt := *opts.Start; opt != "" {
		tm, err := parseDate(opt)
		if err != nil {
			log.Fatalf("failed to parse %q flag: %s", "start", err)
		}
		start = tm
	}
	if opt := *opts.End; opt != "" {
		tm, err := parseDate(opt)
		if err != nil {
			log.Fatalf("failed to parse %q flag: %s", "end", err)
		}
		end = tm
	}

	var matchPrefix string
	if optPrefix := *opts.Prefix; optPrefix != "" {
		matchPrefix = pantherdb.TableName(optPrefix)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:     opts.Region,
		MaxRetries: opts.MaxRetries,
		HTTPClient: opstools.NewHTTPClient(*opts.MaxConnections, 0),
	})
	if err != nil {
		log.Fatalf("failed to build AWS session: %s", err)
	}

	opstools.ValidatePantherVersion(sess, log, *opts.MasterStack, version)

	glueAPI := glue.New(sess)
	s3API := s3.New(sess)
	ctx := context.Background()
	tasks := []gluetasks.RecoverDatabaseTables{
		{
			DatabaseName: pantherdb.LogProcessingDatabase,
			Start:        start,
			End:          end,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
		{
			DatabaseName: pantherdb.RuleErrorsDatabase,
			Start:        start,
			End:          end,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
		{
			DatabaseName: pantherdb.RuleMatchDatabase,
			Start:        start,
			End:          end,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
	}
	group, ctx := errgroup.WithContext(ctx)
	log.Info("recover started")
	for i := range tasks {
		task := &tasks[i]
		group.Go(func() error {
			return task.Run(ctx, glueAPI, s3API, log.Desugar())
		})
	}
	if err := group.Wait(); err != nil {
		log.Errorf("recover failed: %s", err)
	}
	log.Info("recover finished")
}

func parseDate(input string) (time.Time, error) {
	const layoutDate = "2006-01-02"
	tm, err := time.Parse(layoutDate, input)
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "failed to parse %q as date (YYYY-MM-DD)", input)
	}
	return tm, nil
}
