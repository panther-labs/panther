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
	"log"
	"os"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/cmd/devtools/customlogs/customlogs"
	"github.com/panther-labs/panther/cmd/opstools"
)

// CLI commands
const validateCmd = "validate"
const infer = "infer"

func main() {
	opstools.SetUsage(`[infer, validate]`)

	loggerConfig := zap.NewDevelopmentConfig()
	loggerConfig.DisableStacktrace = true
	loggerConfig.DisableCaller = true
	z, err := loggerConfig.Build()
	if err != nil {
		log.Fatalln("failed to start logger: ", err.Error())
	}
	logger := z.Sugar()

	if len(os.Args) < 2 {
		flag.Usage()
		logger.Fatalf("Need to provide one command")
	}

	switch cmd := os.Args[1]; cmd {
	case validateCmd:
		opstools.SetUsage(`-s SCHEMA_FILE [-o OUTPUT_FILE] [INPUT_FILES...]`)
		opts := &customlogs.ValidateOpts{
			Schema: flag.String("s", "", "File file"),
			Output: flag.String("o", "", "Write parsed results to file (defaults to stdout)"),
		}
		if err := flag.CommandLine.Parse(os.Args[2:]); err != nil {
			logger.Fatalf("failed to parse command line arguments")
		}
		customlogs.Validate(logger, opts)
	case infer:
		opstools.SetUsage(`-i INPUT_FILE`)
		opts := &customlogs.InferOpts{
			File:     flag.String("i", "", "Input file"),
			NoVerify: flag.Bool("no-verify", false, "Skips verifying the schema against the logs"),
		}
		if err := flag.CommandLine.Parse(os.Args[2:]); err != nil {
			logger.Fatalf("failed to parse command line arguments")
		}
		customlogs.Infer(logger, opts)
	default:
		flag.Usage()
		logger.Fatalf("Invalid command [%s]", cmd)
	}
}
