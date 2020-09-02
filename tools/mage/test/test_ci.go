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
	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/doc"
	"sort"
	"strings"

	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/tools/mage/util"
)

// Test contains targets for testing code syntax, style, and correctness.
type Test mg.Namespace

type testTask struct {
	Name string
	Task func() error
}

// CI Run all required checks for a pull request
func (Test) CI() {
	// Formatting modifies files (and may generate new ones), so we need to run this first
	fmtErr := testFmtAndGeneratedFiles()

	// Go unit tests and linting already run in multiple processors
	// When running locally, test these by themselves to avoid locking up dev laptops.
	var goUnitErr, goLintErr error
	if !util.IsRunningInCI() {
		goUnitErr = testGoUnit()
		goLintErr = testGoLint()
	}

	tests := []testTask{
		{"fmt", func() error { return fmtErr }},

		// mage test:go
		{"go unit tests", func() error {
			if util.IsRunningInCI() {
				return testGoUnit()
			}
			return goUnitErr
		}},
		{"golangci-lint", func() error {
			if util.IsRunningInCI() {
				return testGoLint()
			}
			return goLintErr
		}},

		// mage doc
		{"doc", doc.doc}, // verify the command works, even if docs aren't committed in this repo
	}

	tests = append(tests, webTests...) // web tests take awhile, queue them earlier
	tests = append(tests, cfnTests...)
	tests = append(tests, pythonTests...)
	runTests(tests)
}

func runTests(tasks []testTask) {
	results := make(chan util.TaskResult)

	done := make(chan struct{})
	go func() {
		defer close(done)
		util.LogResults(results, "test:ci", 1, len(tasks), len(tasks))
	}()

	for _, task := range tasks {
		util.RunTask(results, task.Name, task.Task)
	}
	<-done
}

// Format source files and build APIs and check for changes.
//
// In CI, this returns an error and fails the test if files were not formatted.
// Locally, we only log a warning if files were not formatted (test:ci will still pass).
func testFmtAndGeneratedFiles() error {
	// Formatting is fairly complex: yapf, gofmt, goimports, prettier, docs, license headers, etc
	// It's easier to just run "fmt" and look for changes than to check diffs from each tool individually
	beforeHashes, err := sourceHashes()
	if err != nil {
		return err
	}

	build.build.API()
	build.build.Cfn()
	Fmt()

	afterHashes, err := sourceHashes()
	if err != nil {
		return err
	}

	if diffs := util.FileDiffs(beforeHashes, afterHashes); len(diffs) > 0 {
		sort.Strings(diffs)
		if util.IsRunningInCI() {
			log.Errorf("%d file diffs after build:api + fmt:\n  %s", len(diffs), strings.Join(diffs, "\n  "))
			return fmt.Errorf("%d file diffs after 'mage build:api fmt'", len(diffs))
		}

		log.Warnf("%d file diffs after build:api + fmt:\n  %s", len(diffs), strings.Join(diffs, "\n  "))
		log.Warn("remember to commit formatted files or CI will fail")
	}

	return nil
}
