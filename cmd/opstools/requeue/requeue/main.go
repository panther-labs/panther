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
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/panther-labs/panther/cmd/opstools/requeue"
	"github.com/panther-labs/panther/pkg/prompt"
)

const (
	banner = "moves messages from one sqs queue to another"
)

var (
	REGION      = flag.String("region", "", "The AWS region where the queues exists (optional, defaults to session env vars)")
	FROMQ       = flag.String("from.q", "", "The name of the queue to copy from (defaults to -to.q value with '-dlq' appended)")
	TOQ         = flag.String("to.q", "", "The name of the queue to copy to")
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
		log.Fatal(err)
		return
	}

	if *REGION != "" { //override
		sess.Config.Region = REGION
	}

	promptFlags()
	validateFlags()

	err = requeue.Requeue(sqs.New(sess), *sess.Config.Region, *FROMQ, *TOQ)
	if err != nil {
		log.Fatal(err)
	}
}

func promptFlags() {
	if !*INTERACTIVE {
		return
	}

	if *TOQ == "" {
		*TOQ = prompt.Read("Please enter target queue name to requeue events from associated dead letter queue: ",
			prompt.NonemptyValidator)
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

	if *TOQ == "" {
		err = errors.New("-to.q not set")
		return
	}

	if *FROMQ == "" {
		/*
		  default to our dlq naming convention where:
		    - a queue is <queue prefix>-queue
		    - the associated dlq is <queue prefix>-queue-dlq
		*/
		if strings.HasSuffix(*TOQ, ".fifo") { // these must end in fifo
			baseQueueName := strings.Split(*TOQ, ".")[0]
			*FROMQ = baseQueueName + "-dlq.fifo"
		} else {
			*FROMQ = *TOQ + "-dlq"
		}

		if *VERBOSE || *INTERACTIVE {
			logger.Infof("setting -from.q to default: %s", *FROMQ)
		}
	}
}
