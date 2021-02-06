package util

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
	"runtime"
	"strings"

	"go.uber.org/zap"
)

// MaxWorkers limits CPU-intensive operations depending on the environment.
var MaxWorkers = func() int {
	n := runtime.NumCPU()
	// Use all CPUs in CI environment
	if IsRunningInCI() {
		return n
	}
	// Ensure we don't set maxWorkers to zero
	if n > 1 {
		return n - 1
	}
	return 1
}()

// Queue limiting concurrent tasks when using `runTask`
var taskQueue = make(chan struct{}, MaxWorkers)

// Ugly task queue hack to limit concurrent tasks
func RunTask(results chan<- TaskResult, name string, task func() error) {
	taskQueue <- struct{}{}
	go func() {
		defer func() {
			<-taskQueue
		}()
		results <- TaskResult{
			Summary: name,
			Err:     task(),
		}
	}()
}

// Track results when executing similar tasks in parallel
type TaskResult struct {
	Summary string
	Err     error
}

// Wait for the given number of goroutines to finish, logging results as they come in.
//
// This can be invoked multiple times to track progress over many parallel chunks of work:
//   "start" is the first message number to show in the output
//   "end" is the last message number to show in the output
//   "total" is the total number of tasks (across all invocations)
//
// This will consume exactly (end - start) + 1 messages in the channel.
//
// Returns a combined error message at the end if there were any failures.
func WaitForTasks(log *zap.SugaredLogger, results chan TaskResult, start, end, total int) error {
	var erroredTasks []string
	for i := start; i <= end; i++ {
		r := <-results
		if r.Err == nil {
			log.Infof("    √ %s finished (%d/%d)", r.Summary, i, total)
		} else {
			log.Errorf("    X %s failed (%d/%d): %v", r.Summary, i, total, r.Err)
			erroredTasks = append(erroredTasks, r.Summary)
		}
	}

	if len(erroredTasks) > 0 {
		return fmt.Errorf(strings.Join(erroredTasks, ", "))
	}
	return nil
}
