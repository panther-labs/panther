package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	jsoniter "github.com/json-iterator/go"
)

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

// Wrapper around ioutil.WriteFile, logging errors as fatal.
func writeFile(path string, data []byte) {
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		logger.Fatalf("failed to write %s: %v", path, err)
	}
}

// Build the AWS session from the environment or a credentials file.
func getSession() (*session.Session, error) {
	awsSession, err := session.NewSession()
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

// Get CloudFormation stack outputs as a map.
func getStackOutputs(awsSession *session.Session, name string) (map[string]string, error) {
	cfnClient := cloudformation.New(awsSession)
	input := &cloudformation.DescribeStacksInput{StackName: &name}
	response, err := cfnClient.DescribeStacks(input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe stack %s: %v", name, err)
	}

	return flattenStackOutputs(response), nil
}

// Flatten CloudFormation stack outputs into a string map.
func flattenStackOutputs(detail *cloudformation.DescribeStacksOutput) map[string]string {
	outputs := detail.Stacks[0].Outputs
	result := make(map[string]string, len(outputs))
	for _, output := range outputs {
		result[*output.OutputKey] = *output.OutputValue
	}
	return result
}

// Upload a local file to S3.
func uploadFileToS3(
	awsSession *session.Session, path, bucket, key string, meta map[string]*string) (*s3manager.UploadOutput, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	uploader := s3manager.NewUploader(awsSession)

	logger.Debugf("uploading %s to s3://%s/%s", path, bucket, key)
	return uploader.Upload(&s3manager.UploadInput{
		Body:     file,
		Bucket:   &bucket,
		Key:      &key,
		Metadata: meta,
	})
}

func invokeLambda(awsSession *session.Session, functionName string, input interface{}) error {
	payload, err := jsoniter.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to json marshal input to %s: %v", functionName, err)
	}

	response, err := lambda.New(awsSession).Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(functionName),
		Payload:      payload,
	})
	if err != nil {
		return fmt.Errorf("%s lambda invocation failed: %v", functionName, err)
	}

	if response.FunctionError != nil {
		return fmt.Errorf("%s responded with %s error: %s",
			functionName, *response.FunctionError, string(response.Payload))
	}
	return nil
}

// Prompt the user for a string input.
func promptUser(prompt string, validator func(string) error) string {
	var result string

	for {
		fmt.Print(prompt)
		if n, err := fmt.Scanln(&result); err != nil && n != 0 { // n==0 on empty lines, handled below in validator
			fmt.Println(err)
			continue
		}

		result = strings.TrimSpace(result)
		if err := validator(result); err != nil {
			fmt.Println(err)
			continue
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

// Download a file in memory.
func download(url string) ([]byte, error) {
	logger.Debug("GET " + url)
	response, err := http.Get(url) // nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to GET %s: %v", url, err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %v", url, err)
	}

	return body, nil
}

// isRunningInCI returns true if the mage command is running inside the CI environment
func isRunningInCI() bool {
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
