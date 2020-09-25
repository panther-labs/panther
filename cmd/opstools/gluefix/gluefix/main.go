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
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var opts = struct {
	Recover        *bool
	RecoverEnd     *string
	RecoverStart   *string
	DryRun         *bool
	Debug          *bool
	Region         *string
	NumWorkers     *int
	MaxConnections *int
	MaxRetries     *int
	LogTypePrefix  *string
}{
	RecoverStart:   flag.String("start", "", "Recover partitions after this date YYYY-MM-DD"),
	RecoverEnd:     flag.String("end", "", "Recover partitions until this date YYYY-MM-DD"),
	Recover:        flag.Bool("recover", false, "Try to recover missing table partitions by scanning S3 (slow)"),
	DryRun:         flag.Bool("dry-run", false, "Scan for partitions to update without applying any modifications"),
	Debug:          flag.Bool("debug", false, "Enable additional logging"),
	Region:         flag.String("region", "", "Set the AWS region to run on"),
	MaxRetries:     flag.Int("max-retries", 12, "Max retries for AWS requests"),
	MaxConnections: flag.Int("max-connections", 100, "Max number of connections to AWS"),
	NumWorkers:     flag.Int("workers", 8, "Number of parallel workers for each table"),
	LogTypePrefix:  flag.String("prefix", "", "A prefix to filter log type names"),
}

const layoutDate = "2006-01-02"

func main() {
	flag.Parse()
	logger, err := buildLogger(*opts.Debug)
	if err != nil {
		log.Fatalf("failed to start logger: %s", err)
	}

	sess, err := buildSession()
	if err != nil {
		logger.Fatalf("failed to start AWS session: %s", err)
	}
	ctx := context.Background()
	if *opts.Recover {
		logger.Info("starting to recover partitions")
		err = runRecover(ctx, sess, logger)
	} else {
		logger.Info("starting to sync partitions")
		err = runSync(ctx, sess, logger)
	}
	if err != nil {
		logger.Fatalf("process ended with errors: %s", err)
	}
}

func buildSession() (*session.Session, error) {
	logLevel := aws.LogLevel(aws.LogOff)
	config := aws.Config{
		LogLevel:   logLevel,
		Region:     opts.Region,
		MaxRetries: opts.MaxRetries,
	}
	ss, err := session.NewSession(&config)
	if err != nil {
		return nil, err
	}
	if ss.Config.Region == nil {
		return nil, errors.New("missing AWS region")
	}
	return ss, nil
}

func buildLogger(debug bool) (*zap.SugaredLogger, error) {
	config := zap.NewDevelopmentConfig()
	// Always disable and file/line numbers, error traces and use color-coded log levels and short timestamps
	config.DisableCaller = true
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	if !debug {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
}
