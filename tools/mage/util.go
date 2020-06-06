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
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

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
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(path), err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %v", path, err)
	}
	return nil
}

// Build the AWS session from the environment or a credentials file.
func getSession() (*session.Session, error) {
	awsSession, err := session.NewSession(aws.NewConfig().WithMaxRetries(maxRetries))
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}
	if aws.StringValue(awsSession.Config.Region) == "" {
		return nil, errors.New("no region specified, set AWS_REGION or AWS_DEFAULT_REGION")
	}

	// Load and cache credentials now so we can report a meaningful error
	creds, err := awsSession.Config.Credentials.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			return nil, errors.New("no AWS credentials found, set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
		return nil, fmt.Errorf("failed to load AWS credentials: %v", err)
	}

	logger.Debugw("loaded AWS credentials",
		"provider", creds.ProviderName,
		"region", awsSession.Config.Region,
		"accessKeyId", creds.AccessKeyID)
	return awsSession, nil
}

// Upload a local file to S3.
func uploadFileToS3(awsSession *session.Session, path, bucket, key string) (*s3manager.UploadOutput, error) {
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

// Prompt the user for a string input.
func promptUser(prompt string, validator func(string) error) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		result, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("read string failed: %v\n", err)
			continue
		}

		result = strings.TrimSpace(result)
		if validator != nil {
			if err := validator(result); err != nil {
				fmt.Println(err)
				continue
			}
		}

		return result
	}
}

// Ensure non-empty strings.
func nonemptyValidator(input string) error {
	if len(input) == 0 {
		return errors.New("input is blank, please try again")
	}
	return nil
}

// Very simple email validation to prevent obvious mistakes.
func emailValidator(email string) error {
	if len(email) >= 4 && strings.Contains(email, "@") && strings.Contains(email, ".") {
		return nil
	}
	return errors.New("invalid email: must be at least 4 characters and contain '@' and '.'")
}

func regexValidator(text string) error {
	if _, err := regexp.Compile(text); err != nil {
		return fmt.Errorf("invalid regex: %v", err)
	}
	return nil
}

func dateValidator(text string) error {
	if len(text) == 0 { // allow no date
		return nil
	}
	if _, err := time.Parse("2006-01-02", text); err != nil {
		return fmt.Errorf("invalid date: %v", err)
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
