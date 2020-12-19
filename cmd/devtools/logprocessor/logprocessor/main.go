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
	"compress/gzip"
	"context"
	"flag"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor/logstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

/*
Run log processor locally for profiling purposes.

Profiles can then be visualized with the pprof tool: go tool pprof cpu.prof
*/

var (
	BUCKET          = flag.String("bucket", "", "The bucket to write to.")
	flagSourceID    = flag.String("source-id", "", "The source-id to use.")
	flagSourceLabel = flag.String("source-label", "", "The source-id to use.")
	TOPICARN        = flag.String("topic", "", "The arn for log processor notifications")
	QUEUEURL        = flag.String("queue", "", "The url of the input queue")
	TIMEOUT         = flag.Int("timeout", 900, "timeout in sec")
	FILE            = flag.String("file", "", "The file to process (assumed to be gzipped).")
	LOGTYPE         = flag.String("logtype", "", "The logType.")
	MEMORYSIZE      = flag.Int("lambdaSize", 1024, "The memory size of the lambda")

	VERBOSE = flag.Bool("verbose", false, "verbose logging")

	CPUPROFILE = flag.String("cpuprofile", "", "write cpu profile to `file`")
	MEMPROFILE = flag.String("memprofile", "", "write memory profile to `file`")
)

func main() {
	flag.Parse()

	if *BUCKET == "" {
		log.Fatal("-bucket not set")
	}
	if *TOPICARN == "" {
		log.Fatal("-topic not set")
	}
	if *QUEUEURL == "" {
		log.Fatal("-queue not set")
	}

	os.Setenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", strconv.Itoa(*MEMORYSIZE))
	os.Setenv("S3_BUCKET", *BUCKET)
	os.Setenv("SNS_TOPIC_ARN", *TOPICARN)
	os.Setenv("SQS_QUEUE_URL", *QUEUEURL)
	os.Setenv("TIME_LIMIT_SEC", strconv.Itoa(*TIMEOUT))

	log.Printf("cores: %d", runtime.NumCPU())
	log.Printf("input %s", *FILE)

	fileReader, err := os.Open(*FILE)
	if err != nil {
		log.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(fileReader)
	if err != nil {
		log.Fatal(err)
	}
	streamChan := make(chan *common.DataStream, 1)

	var logTypes []string
	if *LOGTYPE != "" {
		logTypes = append(logTypes, *LOGTYPE)
	} else {
		// Use all available log types
		logTypes = logtypes.CollectNames(registry.NativeLogTypes())
	}

	dataStream := &common.DataStream{
		Stream: logstream.NewLineStream(gzipReader, logstream.DefaultBufferSize),
		Source: &models.SourceIntegration{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    *flagSourceID,
				IntegrationType:  models.IntegrationTypeAWS3,
				IntegrationLabel: *flagSourceLabel,
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "", LogTypes: logTypes}},
			},
		},
	}

	streamChan <- dataStream
	close(streamChan)

	if *CPUPROFILE != "" {
		f, err := os.Create(*CPUPROFILE)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	var config zap.Config
	if *VERBOSE {
		config = zap.NewDevelopmentConfig()
	} else {
		config = zap.NewProductionConfig()
	}
	logger, err := config.Build()
	if err != nil {
		log.Fatal("failed to build zap logger: " + err.Error())
	}
	zap.ReplaceGlobals(logger)
	// Use a properly configured JSON instance with AWS Glue quirks
	jsonAPI := common.ConfigForDataLakeWriters()

	// Use the global registry
	dest := destinations.CreateS3Destination(jsonAPI)

	newProcessor := processor.NewFactory(registry.NativeLogTypesResolver())
	err = processor.Process(context.Background(), streamChan, dest, newProcessor)
	if err != nil {
		log.Fatal(err)
	}

	if *MEMPROFILE != "" {
		f, err := os.Create(*MEMPROFILE)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		runtime.GC()    // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}
