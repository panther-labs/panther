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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var (
	goTargets = []string{"api", "internal", "pkg", "tools", "cmd", "magefile.go"}
	pyTargets = []string{
		"internal/compliance/remediation_aws",
		"internal/compliance/policy_engine",
		"internal/log_analysis/rules_engine"}
)

// Fmt Format source files
func Fmt() {
	// Add license headers first (don't run in parallel with other formatters)
	fmtLicenseAll()

	results := make(chan goroutineResult)
	count := 0

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"fmt: gofmt", gofmt(goTargets...)}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"fmt: go mod tidy", goModTidy()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"fmt: yapf", yapf(pyTargets...)}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"fmt: prettier", prettier("")}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"fmt: tf", terraformFmt()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"docs", doc()}
	}(results)

	logResults(results, "fmt", 1, count, count)
}

// Apply full go formatting to the given paths
func gofmt(paths ...string) error {
	logger.Debug("fmt: gofmt " + strings.Join(paths, " "))

	// 1) gofmt to standardize the syntax formatting with code simplification (-s) flag
	if err := sh.Run("gofmt", append([]string{"-l", "-s", "-w"}, paths...)...); err != nil {
		return fmt.Errorf("gofmt failed: %v", err)
	}

	// 2) Remove empty newlines from import groups
	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("stat %s: %v", path, err)
			}

			if !info.IsDir() && strings.HasSuffix(path, ".go") {
				if err := removeImportNewlines(path); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// 3) Goimports to group imports into 3 sections
	args := append([]string{"-w", "-local=github.com/panther-labs/panther"}, paths...)
	if err := sh.Run("goimports", args...); err != nil {
		return fmt.Errorf("goimports failed: %v", err)
	}

	return nil
}

// Remove empty newlines from formatted import groups so goimports will correctly group them.
func removeImportNewlines(path string) error {
	var newLines [][]byte
	inImport := false
	for _, line := range bytes.Split(readFile(path), []byte("\n")) {
		if inImport {
			if len(line) == 0 {
				continue // skip empty newlines in import groups
			}
			if line[0] == ')' { // gofmt always puts the ending paren on its own line
				inImport = false
			}
		} else if bytes.HasPrefix(line, []byte("import (")) {
			inImport = true
		}

		newLines = append(newLines, line)
	}

	return ioutil.WriteFile(path, bytes.Join(newLines, []byte("\n")), 0644)
}

// Tidy go.mod/go.sum
func goModTidy() error {
	return sh.Run("go", "mod", "tidy")
}

// Apply Python formatting to the given paths
func yapf(paths ...string) error {
	logger.Debug("fmt: python yapf " + strings.Join(paths, " "))
	args := []string{"--in-place", "--parallel", "--recursive"}
	if err := sh.Run(pythonLibPath("yapf"), append(args, pyTargets...)...); err != nil {
		return fmt.Errorf("failed to format python: %v", err)
	}
	return nil
}

// Apply prettier formatting to web, markdown, and yml files
func prettier(pathPattern string) error {
	if pathPattern == "" {
		pathPattern = "**/*.{ts,js,tsx,md,json,yaml,yml}"
	}
	logger.Debug("fmt: prettier " + pathPattern)
	args := []string{"--write", pathPattern}
	if !mg.Verbose() {
		args = append(args, "--loglevel", "error")
	}

	if err := sh.Run(nodePath("prettier"), args...); err != nil {
		return fmt.Errorf("failed to format with prettier: %v", err)
	}
	return nil
}

// Apply Terraform formatting to aux templates
func terraformFmt() error {
	root := filepath.Join("deployments", "auxiliary", "terraform")
	return sh.Run(terraformPath, "fmt", "-recursive", root)
}
