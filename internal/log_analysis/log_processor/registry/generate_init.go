//+build ignore

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
	"go/format"
	"io/ioutil"
	"log"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry/internal"
)

var opts = struct {
	Filename *string
}{
	Filename: flag.String("f", "init.go", "Filename to write"),
}

// main scans packages for exported log types and generates a go file to initialize the registry log types
func main() {
	flag.Parse()
	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"."}
	}
	packages, err := internal.LoadExportedLogTypes(patterns...)
	if err != nil {
		log.Fatalf("failed to discover log types %v: %s", patterns, err)
	}
	src, err := internal.GenerateInit("registry/generate_init.go", packages...)
	if err != nil {
		log.Fatalf("failed to generate code: %s", err)
	}
	formatted, err := format.Source(src)
	if err != nil {
		log.Fatalf("failed to format code: %s", err)
	}

	if err := ioutil.WriteFile(*opts.Filename, formatted, 0600); err != nil {
		log.Fatalln("failed to write file", err)
	}
}
