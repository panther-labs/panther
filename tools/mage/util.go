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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"gopkg.in/yaml.v2"
)

// Open and parse a yaml file.
func loadYamlFile(path string, out interface{}) error {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %s", path, err)
	}

	if err := yaml.Unmarshal(contents, out); err != nil {
		return fmt.Errorf("failed to parse yaml file '%s': %s", path, err)
	}

	return nil
}

// Get CloudFormation stack outputs as a map.
func getStackOutputs(awsSession *session.Session, name string) (map[string]string, error) {
	cfnClient := cloudformation.New(awsSession)
	input := &cloudformation.DescribeStacksInput{StackName: &name}
	response, err := cfnClient.DescribeStacks(input)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(response.Stacks[0].Outputs))
	for _, output := range response.Stacks[0].Outputs {
		result[aws.StringValue(output.OutputKey)] = aws.StringValue(output.OutputValue)
	}

	return result, nil
}

// Upload a local file to S3.
func uploadFileToS3(
	awsSession *session.Session, path, bucket, key string, meta map[string]*string) (*s3manager.UploadOutput, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	uploader := s3manager.NewUploader(awsSession)
	fmt.Printf("deploy: uploading %s to s3://%s/%s\n", path, bucket, key)
	return uploader.Upload(&s3manager.UploadInput{
		Body:     file,
		Bucket:   &bucket,
		Key:      &key,
		Metadata: meta,
	})
}

// Prompt the user for a string input.
func promptUser(prompt string, validator func(string) error) string {
	var result string

	for {
		fmt.Print(prompt)
		if _, err := fmt.Scanln(&result); err != nil {
			fmt.Println(err) // empty line, for example
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
		return errors.New("error: input is blank, please try again")
	}
	return nil
}

// Very simple email validation to prevent obvious mistakes.
func emailValidator(email string) error {
	if len(email) >= 4 && strings.Contains(email, "@") && strings.Contains(email, ".") {
		return nil
	}

	return errors.New("error: invalid email: must be at least 4 characters and contain '@' and '.'")
}

// Download a file in memory.
func download(url string) ([]byte, error) {
	response, err := http.Get(url) // nolint:gosec
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return ioutil.ReadAll(response.Body)
}

// isRunningInCI returns true if the mage command is running inside
// CI environment
func isRunningInCI() bool {
	return os.Getenv("CI") != ""
}
