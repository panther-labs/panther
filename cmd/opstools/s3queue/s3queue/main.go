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
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/cmd/opstools/s3list"
	"github.com/panther-labs/panther/cmd/opstools/s3queue"
	"github.com/panther-labs/panther/pkg/prompt"
)

const (
	banner = "lists s3 objects and posts s3 notifications to log processor queue"
)

var (
	REGION      = flag.String("region", "", "The Panther AWS region (optional, defaults to session env vars) where the queue exists.")
	ACCOUNT     = flag.String("account", "", "The Panther AWS account id (optional, defaults to session account)")
	S3PATH      = flag.String("s3path", "", "The s3 path to list (e.g., s3://<bucket>/<prefix>).")
	CONCURRENCY = flag.Int("concurrency", 50, "The number of concurrent sqs writer go routines")
	LIMIT       = flag.Uint64("limit", 0, "If non-zero, then limit the number of files to this number.")
	TOQ         = flag.String("queue", "panther-input-data-notifications-queue", "The name of the log processor queue to send notifications.")
	RATE        = flag.Float64("files-per-second", 0.0, "If non-zero, attempt to send at this rate of files per second")
	DURATION    = flag.Duration("duration", 0, "If non-zero, stop after this long")
	LOOP        = flag.Bool("loop", false, "If true, after finishing, repeat.")
	INTERACTIVE = flag.Bool("interactive", true, "If true, prompt for required flags if not set")
	DEBUG       = flag.Bool("debug", false, "Enable debug logging")

	logger *zap.SugaredLogger
)

func main() {
	opstools.SetUsage(banner)

	flag.Parse()

	logger = opstools.MustBuildLogger(*DEBUG)

	sess, err := session.NewSession()
	if err != nil {
		logger.Fatal(err)
		return
	}

	if *REGION != "" { //override
		sess.Config.Region = REGION
	} else {
		REGION = sess.Config.Region
	}

	promptFlags()
	validateFlags()

	if *ACCOUNT == "" {
		identity, err := sts.New(sess).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			logger.Fatalf("failed to get caller identity: %v", err)
		}
		ACCOUNT = identity.Account
	}

	s3Region, err := s3list.GetS3Region(sess, *S3PATH)
	if err != nil {
		logger.Fatalf("%v", err)
	}

	startTime := time.Now()
	if *LIMIT > 0 {
		logger.Debugf("sending %d files from %s in %s to %s in %s",
			LIMIT, *S3PATH, s3Region, *TOQ, *REGION)
	} else {
		logger.Debugf("sending files from %s in %s to %s in %s",
			*S3PATH, s3Region, *TOQ, *REGION)
	}

	input := &s3queue.Input{
		DriverInput: s3queue.DriverInput{
			Logger:         logger,
			Account:        *ACCOUNT,
			QueueName:      *TOQ,
			Concurrency:    *CONCURRENCY,
			FilesPerSecond: *RATE,
			Duration:       *DURATION,
		},
		Session:  sess,
		S3Path:   *S3PATH,
		S3Region: s3Region,
		Limit:    *LIMIT,
		Loop:     *LOOP,
	}

	// catch ^C
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		caught := <-sig // wait for it
		logger.Fatalf("caught %v, sent %d files (%.2fMB) to %s in %v",
			caught, input.Stats.NumFiles, float32(input.Stats.NumBytes)/(1024.0*1024.0), *TOQ, time.Since(startTime))
	}()

	err = s3queue.S3Queue(context.TODO(), input)
	if err != nil {
		logger.Fatal(err)
	} else {
		logger.Infof("sent %d files (%.2fMB) to %s (%s) in %v",
			input.Stats.NumFiles, float32(input.Stats.NumBytes)/(1024.0*1024.0), *TOQ, *REGION, time.Since(startTime))
	}
}

func promptFlags() {
	if !*INTERACTIVE {
		return
	}

	if *S3PATH == "" {
		*S3PATH = prompt.Read("Please enter the s3 path to read from (e.g., s3://<bucket>/<prefix>): ", prompt.NonemptyValidator)
	}

	if *TOQ == "" {
		*TOQ = prompt.Read("Please enter queue name to write to: ", prompt.NonemptyValidator)
	}
}

func validateFlags() {
	var err error
	defer func() {
		if err != nil {
			fmt.Printf("%s\n", err)
			flag.Usage()
			os.Exit(-2)
		}
	}()

	if *CONCURRENCY <= 0 {
		err = errors.New("-concurrency must be > 0")
		return
	}
	// This ensures more continuous average activity for small FPS
	if *RATE > 0 && float64(*CONCURRENCY) > *RATE {
		*CONCURRENCY = int(*RATE)
	}

	if *S3PATH == "" {
		err = errors.New("-s3path not set")
		return
	}
	if *TOQ == "" {
		err = errors.New("-queue not set")
		return
	}

	if *RATE < 0.0 {
		err = errors.New("-rate must be >= 0.0")
		return
	}
}
