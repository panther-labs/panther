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
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/panther-labs/panther/cmd/opstools/s3sns"
	"github.com/panther-labs/panther/pkg/prompt"
)

const (
	banner = "lists s3 objects and posts s3 notifications to log processor sns topic"
)

var (
	REGION = flag.String("region", "",
		"The Panther AWS region (optional, defaults to session env vars) where the topic exists.")
	ACCOUNT = flag.String("account", "",
		"The Panther AWS account id (optional, defaults to session account)")
	S3PATH      = flag.String("s3path", "", "The s3 path to list (e.g., s3://<bucket>/<prefix>).")
	CONCURRENCY = flag.Int("concurrency", 50, "The number of concurrent sqs writer go routines")
	LIMIT       = flag.Uint64("limit", 0,
		"If non-zero, then limit the number of files to this number.")
	TOPIC = flag.String("topic", "panther-processed-data-notifications",
		"The name of the log processor topic to send notifications.")
	ATTRIBUTES = flag.Bool("attributes", false,
		"If true, add SNS attributes that would enable the rule engine and datacatalog updater to receive events.")
	INTERACTIVE = flag.Bool("interactive", true, "If true, prompt for required flags if not set")
	VERBOSE     = flag.Bool("verbose", false, "Enable verbose logging")

	logger *zap.SugaredLogger
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		"%s %s\nUsage:\n",
		filepath.Base(os.Args[0]), banner)
	flag.PrintDefaults()
}

func init() {
	flag.Usage = usage
}

func logInit() {
	config := zap.NewDevelopmentConfig() // DEBUG by default
	if !*VERBOSE {
		// In normal mode, hide DEBUG messages
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	// Always disable and file/line numbers, error traces and use color-coded log levels and short timestamps
	config.DisableCaller = true
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	rawLogger, err := config.Build()
	if err != nil {
		log.Fatalf("failed to build logger: %s", err)
	}
	zap.ReplaceGlobals(rawLogger)
	logger = rawLogger.Sugar()
}

func main() {
	flag.Parse()

	logInit() // must be done after parsing flags

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

	s3Region := getS3Region(sess, *S3PATH)

	if *ACCOUNT == "" {
		identity, err := sts.New(sess).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			logger.Fatalf("failed to get caller identity: %v", err)
		}
		ACCOUNT = identity.Account
	}

	startTime := time.Now()
	if *VERBOSE {
		if *LIMIT > 0 {
			logger.Infof("sending %d files from %s in %s to %s in %s",
				LIMIT, *S3PATH, s3Region, *TOPIC, *REGION)
		} else {
			logger.Infof("sending files from %s in %s to %s in %s",
				*S3PATH, s3Region, *TOPIC, *REGION)
		}
	}

	stats := &s3sns.Stats{}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		caught := <-sig // wait for it
		logger.Fatalf("caught %v, sent %d files (%.2fMB) to %s in %v",
			caught, stats.NumFiles, float32(stats.NumBytes)/(1024.0*1024.0), *TOPIC, time.Since(startTime))
	}()

	err = s3sns.S3Topic(sess, *ACCOUNT, *S3PATH, s3Region, *TOPIC, *ATTRIBUTES, *CONCURRENCY, *LIMIT, stats)
	if err != nil {
		logger.Fatal(err)
	} else {
		logger.Infof("sent %d files (%.2fMB) to %s (%s) in %v",
			stats.NumFiles, float32(stats.NumBytes)/(1024.0*1024.0), *TOPIC, *REGION, time.Since(startTime))
	}
}

func promptFlags() {
	if !*INTERACTIVE {
		return
	}

	if *S3PATH == "" {
		*S3PATH = prompt.Read("Please enter the s3 path to read from (e.g., s3://<bucket>/<prefix>): ", prompt.NonemptyValidator)
	}

	if *TOPIC == "" {
		*TOPIC = prompt.Read("Please enter topic name to write to: ", prompt.NonemptyValidator)
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

	if *S3PATH == "" {
		err = errors.New("-s3path not set")
		return
	}
	if *TOPIC == "" {
		err = errors.New("-topic not set")
		return
	}
}

func getS3Region(sess *session.Session, s3Path string) string {
	parsedPath, err := url.Parse(s3Path)
	if err != nil {
		logger.Fatalf("failed to find bucket region for provided path %s: %s", s3Path, err)
	}

	input := &s3.GetBucketLocationInput{Bucket: aws.String(parsedPath.Host)}
	location, err := s3.New(sess).GetBucketLocation(input)
	if err != nil {
		logger.Fatalf("failed to find bucket region for provided path %s: %s", s3Path, err)
	}

	// Method may return nil if region is us-east-1,https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
	// and https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
	if location.LocationConstraint == nil {
		return endpoints.UsEast1RegionID
	}
	return *location.LocationConstraint
}
