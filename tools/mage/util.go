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
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Package global set by getSession()
var awsSession *session.Session

const (
	maxRetries = 20 // try very hard, avoid throttles
)

// For CPU-intensive operations, limit the max number of worker goroutines.
var maxWorkers = func() int {
	n := runtime.NumCPU()
	// Use all CPUs on CI environment
	if runningInCI() {
		return n
	}
	// Ensure we don't set maxWorkers to zero
	if n > 1 {
		return n - 1
	}
	return 1
}()

// Queue limiting concurrent tasks when using `runTask`
var taskQueue = make(chan struct{}, maxWorkers)

// Ugly task queue hack to limit concurrent tasks
func runTask(results chan<- goroutineResult, name string, task func() error) {
	taskQueue <- struct{}{}
	go func() {
		defer func() {
			<-taskQueue
		}()
		results <- goroutineResult{
			summary: name,
			err:     task(),
		}
	}()
}

// Track results when executing similar tasks in parallel
type goroutineResult struct {
	summary string
	err     error
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
// Logs a fatal message at the end if there were any errors.
func logResults(results chan goroutineResult, command string, start, end, total int) {
	var erroredTasks []string
	for i := start; i <= end; i++ {
		r := <-results
		if r.err == nil {
			logger.Infof("    √ %s finished (%d/%d)", r.summary, i, total)
		} else {
			logger.Errorf("    X %s failed (%d/%d): %v", r.summary, i, total, r.err)
			erroredTasks = append(erroredTasks, r.summary)
		}
	}

	if len(erroredTasks) > 0 {
		logger.Fatalf("%s failed: %s", command, strings.Join(erroredTasks, ", "))
	}
}

// Wrapper around filepath.Walk, logging errors as fatal.
func walk(root string, handler func(string, os.FileInfo)) {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("stat %s: %v", path, err)
		}
		handler(path, info)
		return nil
	})
	if err != nil {
		logger.Fatalf("couldn't traverse %s: %v", root, err)
	}
}

// Wrapper around ioutil.ReadFile, logging errors as fatal.
func readFile(path string) []byte {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Fatalf("failed to read %s: %v", path, err)
	}
	return contents
}

// Wrapper around ioutil.WriteFile, creating the parent directories if needed.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(path), err)
	}

	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write file %s: %v", path, err)
	}
	return nil
}

// Build awsSession global from the environment or a credentials file
func getSession() {
	var err error
	awsSession, err = session.NewSession(aws.NewConfig().WithMaxRetries(maxRetries))
	if err != nil {
		logger.Fatalf("failed to create AWS session: %v", err)
	}
	if aws.StringValue(awsSession.Config.Region) == "" {
		logger.Fatalf("no region specified, set AWS_REGION or AWS_DEFAULT_REGION")
	}

	// Load and cache credentials now so we can report a meaningful error
	creds, err := awsSession.Config.Credentials.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			logger.Fatalf("no AWS credentials found, set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
		logger.Fatalf("failed to load AWS credentials: %v", err)
	}

	logger.Debugw("loaded AWS credentials",
		"provider", creds.ProviderName,
		"region", awsSession.Config.Region,
		"accessKeyId", creds.AccessKeyID)
}

// Set global gitVersion, warn if not deploying a tagged release
func getGitVersion(warnWhenUntagged bool) {
	var err error
	gitVersion, err = sh.Output("git", "describe", "--tags")
	if err != nil {
		logger.Fatalf("git describe failed: %v", err)
	}
	// The gitVersion is "v0.3.0" on tagged release, otherwise something like "v0.3.0-128-g77fd9ff"
	if warnWhenUntagged && strings.Contains(gitVersion, "-") {
		logger.Warnf("%s is not a tagged release, proceed at your own risk", gitVersion)
	}
}

// Upload a local file to S3.
func uploadFileToS3(path, bucket, key string) (*s3manager.UploadOutput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	uploader := s3manager.NewUploader(awsSession)

	logger.Debugf("uploading %s to s3://%s/%s", path, bucket, key)
	return uploader.Upload(&s3manager.UploadInput{
		Body:   file,
		Bucket: &bucket,
		Key:    &key,
	})
}

// Run a command, capturing stdout and stderr unless the command errors or we're in verbose mode.
//
// This is helpful for tools which print unwanted info to stderr even when successful or, conversely,
// tools which output failing tests to stdout that we want to show even in non-verbose mode.
//
// Both outputs will be printed if the command returns an error.
//
// Similar to sh.Run(), except sh.Run() only hides stdout in non-verbose mode.
func runWithCapturedOutput(cmd string, args ...string) error {
	if mg.Verbose() {
		return sh.Run(cmd, args...)
	}

	var buf bytes.Buffer
	if _, err := sh.Exec(nil, &buf, &buf, cmd, args...); err != nil {
		// The command failed - in non-verbose mode, all output has been hidden.
		// We need to print the output so the user can see the error message.
		fmt.Println(buf.String())
		return err
	}

	return nil
}

// runningInCI returns true if the mage command is running inside the CI environment
func runningInCI() bool {
	return os.Getenv("CI") != ""
}

// pythonLibPath the Python venv path of the given library
func pythonLibPath(lib string) string {
	return filepath.Join(pythonVirtualEnvPath, "bin", lib)
}

// Path to a node binary
func nodePath(binary string) string {
	return filepath.Join("node_modules", ".bin", binary)
}
