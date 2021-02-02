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

// This tool's purpose is to test parsers and classifier against sample log files locally at the CLI using pipes.
// It reads logs from `stdin`, classifies each log line writing the resulting JSON to `stdout`.
// When the `-debug` flag is passed it writes information about parsing to `stderr`
// Example usage:
// $ cat foo/bar/sample.log | pantherlog
// $ cat foo/bar/sample.log bar/baz/sample.log | pantherlog
// $ cat foo/bar/sample.log bar/baz/sample.log | pantherlog -debug

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor/logstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

var (
	debug       = flag.Bool("debug", false, "Log debug to stderr")
	sourceID    = flag.String("source-id", "", "Set source id")
	sourceLabel = flag.String("source-label", "", "Set source label")
)

func main() {
	flag.Parse()

	stdin := os.Stdin
	var stderr io.Writer
	if *debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Writing debug output\n")
		stderr = os.Stderr
	} else {
		stderr = ioutil.Discard
	}

	debugLog := log.New(stderr, "[DEBUG] ", log.LstdFlags)

	stdout := os.Stdout
	out := bufio.NewWriter(stdout)
	defer out.Flush()

	jsonAPI := common.ConfigForDataLakeWriters()

	parsers := availableParsers()

	classifier := classification.NewClassifier(parsers)
	stream := logstream.NewLineStream(stdin, logstream.DefaultBufferSize)
	numLines := 0
	numEvents := 0

	for {
		next := stream.Next()
		if next == nil {
			break
		}
		line := string(next)
		if len(line) == 0 {
			debugLog.Printf("Empty line %d\n", numLines)
			continue
		}
		numLines++
		result, err := classifier.Classify(line)
		if err != nil {
			debugLog.Printf("Failed to classify line %d: %s\n", numLines, err)
			os.Exit(1)
		}
		debugLog.Printf("Line=%d NumEvents=%d\n", numLines, len(result.Events))
		for _, event := range result.Events {
			// Add source fields
			event.PantherSourceID = *sourceID
			event.PantherSourceLabel = *sourceLabel

			data, err := jsonAPI.Marshal(event)
			if err != nil {
				log.Fatal(err)
			}
			if _, err := out.Write(data); err != nil {
				log.Fatal(err)
			}
			if err := out.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}
			numEvents++
		}
	}
	if err := stream.Err(); err != nil {
		debugLog.Printf("Read failed at line %d: %s", numLines, err)
		os.Exit(1)
	}
	debugLog.Printf("Scanned %d lines\n", numLines)
	debugLog.Printf("Parsed %d events\n", numEvents)
}

// availableParsers returns log parsers for all native log types with nil parameters.
// Panics if a parser factory in the default registry fails with nil params.
func availableParsers() map[string]parsers.Interface {
	entries := registry.NativeLogTypes().Entries()
	available := make(map[string]parsers.Interface, len(entries))
	for _, entry := range entries {
		logType := entry.String()
		parser, err := entry.NewParser(nil)
		if err != nil {
			panic(errors.Errorf("failed to create %q parser with nil params", logType))
		}
		available[logType] = parser
	}
	return available
}
