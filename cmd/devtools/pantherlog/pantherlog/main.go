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
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/unbox"
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
		w := bufio.NewWriter(os.Stderr)
		defer w.Flush()
		stderr = w
	} else {
		stderr = ioutil.Discard
	}

	debugLog := log.New(stderr, "[DEBUG] ", log.LstdFlags)

	stdout := os.Stdout
	out := bufio.NewWriter(stdout)
	defer out.Flush()

	jsonAPI := common.BuildJSON()
	src := parsers.SourceParams{
		SourceID:    *sourceID,
		SourceLabel: *sourceLabel,
	}

	parsers := registry.AvailableParsers(src)

	classifier := classification.NewClassifier(parsers)
	lines := bufio.NewScanner(stdin)
	n := 0
	for lines.Scan() {
		line := lines.Text()
		if line == "" {
			debugLog.Printf("Empty line %d\n", n)
			continue
		}
		n++
		result := classifier.Classify(line)
		if result == nil {
			debugLog.Printf("Failed to classify line %d\n", n)
			os.Exit(1)
		}
		debugLog.Printf("Line=%d Type=%q NumEvents=%d\n", n, unbox.String(result.LogType), len(result.Events))
		for _, event := range result.Events {
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
		}
	}
	if err := lines.Err(); err != nil {
		debugLog.Printf("Scan failed %s\n", err)
		os.Exit(1)
	}
	debugLog.Printf("Scanned %d lines\n", n)
}
