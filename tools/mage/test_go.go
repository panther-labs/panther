package mage

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
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Test and lint Golang source code
func (Test) Go() {
	if err := testGoUnit(); err != nil {
		logger.Fatalf("go unit tests failed: %v", err)
	}

	if err := testGoLint(); err != nil {
		logger.Fatalf("go linting failed: %v", err)
	}
}

func testGoUnit() error {
	logger.Info("test:go: running go unit tests")
	runGoTest := func(args ...string) error {
		if mg.Verbose() {
			// verbose mode - show "go test" output (all package names)
			return sh.Run("go", args...)
		}

		// standard mode - filter output to show only the errors
		var output string
		output, err := sh.Output("go", args...)
		if err != nil {
			for _, line := range strings.Split(output, "\n") {
				if !strings.HasPrefix(line, "ok  	github.com/panther-labs/panther") &&
					!strings.HasPrefix(line, "?   	github.com/panther-labs/panther") {

					fmt.Println(line)
				}
			}
		}
		return err
	}

	// unit tests and race detection
	return runGoTest("test", "-race", "-p", strconv.Itoa(maxWorkers), "-vet", "", "-cover", "./...")
}

func testGoLint() error {
	logger.Info("test:go: running go metalinter")
	args := []string{"run", "--timeout", "10m", "-j", strconv.Itoa(maxWorkers)}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	return sh.RunV(filepath.Join(setupDirectory, "golangci-lint"), args...)
}
