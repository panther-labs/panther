package test

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
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

type testTask struct {
	Name string
	Task func() error
}

var log = logger.Build("[test]")

// Equivalent to test:go test:web test:cfn test:python
//
// CircleCI is configured to run test groups separately, it does not call this function.
func CI() error {
	log = logger.Build("[test:ci]")

	// Go unit tests and linting already run in multiple processors
	goUnitErr := testGoUnit()
	goLintErr := testGoLint()

	tests := []testTask{
		// mage test:go
		{"go unit tests", func() error {
			return goUnitErr
		}},
		{"golangci-lint", func() error {
			return goLintErr
		}},
	}

	tests = append(tests, webTests...) // web tests take awhile, queue them earlier
	tests = append(tests, cfnTests...)
	tests = append(tests, pythonTests...)
	return runTests(tests)
}

func runTests(tasks []testTask) (err error) {
	results := make(chan util.TaskResult)

	done := make(chan struct{})
	go func() {
		defer close(done)
		err = util.WaitForTasks(log, results, 1, len(tasks), len(tasks))
	}()

	for _, task := range tasks {
		util.RunTask(results, task.Name, task.Task)
	}
	<-done

	return
}
