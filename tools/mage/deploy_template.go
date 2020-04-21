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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/magefile/mage/sh"
)

const (
	maxTemplateSize = 51200 // Max file size before CFN templates must be uploaded to S3

	pollInterval = 5 * time.Second // How long to wait in between requests to the CloudFormation service
	pollTimeout  = time.Hour       // Give up if CreateChangeSet or ExecuteChangeSet takes longer than this
)

var (
	gitVersion string // set in deployPrecheck()
)

// Deploy a CloudFormation template.
//
// 1) Package: Upload large assets (GraphQL schema, Lambda source, nested templates) to S3 with aws cli
// 2) Post-processing: Fix packaged template URLs with a region-agnostic link
// 3) Deploy: Create and execute a change set
//
// The bucket parameter can be empty to skip S3 packaging.
// The stack outputs are returned to the caller, errors are considered fatal and will halt execution.
func deployTemplate(
	awsSession *session.Session, templatePath, bucket, stack string, params map[string]string) map[string]string {

	if bucket != "" {
		templatePath = cfnPackage(templatePath, bucket, stack)
	}

	client := cloudformation.New(awsSession)

	changeID, outputs := createChangeSet(awsSession, client, templatePath, bucket, stack, params)
	if changeID == nil {
		return outputs
	}

	return executeChangeSet(client, changeID, stack)
}

// Upload resources to S3 and return the path to the modified CloudFormation template.
// TODO - implement this directly to avoid the aws cli (https://github.com/panther-labs/panther/issues/136)
func cfnPackage(templatePath, bucket, stack string) string {
	outputDir := filepath.Dir(templatePath)
	if !strings.HasPrefix(outputDir, "out") {
		outputDir = filepath.Join("out", outputDir)
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Fatalf("failed to create directory %s: %v", outputDir, err)
	}

	// There is no equivalent to this command in the AWS Go SDK.
	pkgOut := filepath.Join(outputDir, "package."+filepath.Base(templatePath))
	args := []string{"cloudformation", "package",
		"--output-template-file", pkgOut,
		"--s3-bucket", bucket,
		"--s3-prefix", stack,
		"--template-file", templatePath,
	}

	// Discard the output unless running in verbose mode
	logger.Infof("deploy: packaging %s assets in s3://%s", templatePath, bucket)
	if err := sh.Run("aws", args...); err != nil {
		logger.Fatalf("aws cloudformation package %s failed: %v", templatePath, err)
	}

	// Post-processing: fix templateURLs to be region-agnostic
	var result []string
	for _, line := range strings.Split(string(readFile(pkgOut)), "\n") {
		result = append(result, fixPackageTemplateURL(line))
	}

	writeFile(pkgOut, []byte(strings.Join(result, "\n")))
	return pkgOut
}

// Fix CloudFormation package TemplateURL issues.
// Somewhere there is a bug that is causing the environment variables specifying region to not be properly respected
// when constructing the template URLs while deploying to another region than the one specified in the aws config.
//
// I believe it is related to this issue: https://github.com/aws/aws-cli/issues/4372
func fixPackageTemplateURL(line string) string {
	// This code transforms:
	// TemplateURL: https://s3.region.amazonaws.com/bucket/panther-app/1.template
	// into:
	// TemplateURL: https://s3.amazonaws.com/bucket/panther-app/1.template
	// Unless that is the format the URL was already in.
	if strings.HasPrefix(strings.TrimSpace(line), "TemplateURL: ") {
		// Break the line down to the pieces we need
		lineParts := strings.Split(line, "https://")
		uriParts := strings.Split(lineParts[1], "/")
		prefixParts := strings.Split(uriParts[0], ".")

		// Check if the format is already correct
		if prefixParts[1] == "amazonaws" {
			return line
		}

		// Build the new URI
		prefixParts[1] = "s3"
		newURIPrefix := strings.Join(prefixParts[1:], ".")
		newURIParts := append([]string{newURIPrefix}, uriParts[1:]...)
		lineParts[1] = strings.Join(newURIParts, "/")
		line = strings.Join(lineParts, "https://")
	}

	return line
}

// Create a CloudFormation change set, returning its name.
//
// If there are pending changes, the change set id and no outputs are returned.
// Otherwise, the change set is deleted and a nil id with the stack outputs are returned.
func createChangeSet(
	awsSession *session.Session,
	client *cloudformation.CloudFormation,
	templateFile, bucket, stack string,
	params map[string]string,
) (*string, map[string]string) {

	// Change set type - CREATE if a new stack otherwise UPDATE
	stackDetail, err := client.DescribeStacks(&cloudformation.DescribeStacksInput{StackName: &stack})
	changeSetType := "CREATE"
	if err == nil && len(stackDetail.Stacks) > 0 {
		// Check if the previous deployment timed out and is still going, if so continue where that left off
		if status := *stackDetail.Stacks[0].StackStatus; strings.Contains(status, cloudformation.OperationStatusInProgress) {
			logger.Warnf("deploy: %s already in state %s, resuming previous deployment", stack, status)
			return stackDetail.Stacks[0].ChangeSetId, nil
		}
		changeSetType = "UPDATE"
	}

	parameters := make([]*cloudformation.Parameter, 0, len(params))
	for key, val := range params {
		parameters = append(parameters, &cloudformation.Parameter{
			ParameterKey:   aws.String(key),
			ParameterValue: aws.String(val),
		})
	}

	// add version tag to all objects ("untagged" if not set)
	pantherVersion := gitVersion
	if pantherVersion == "" {
		pantherVersion = "untagged"
	}

	createInput := &cloudformation.CreateChangeSetInput{
		Capabilities: []*string{
			aws.String("CAPABILITY_AUTO_EXPAND"),
			aws.String("CAPABILITY_IAM"),
			aws.String("CAPABILITY_NAMED_IAM"),
		},
		ChangeSetName: aws.String(fmt.Sprintf("panther-%d", time.Now().UnixNano())),
		ChangeSetType: &changeSetType,
		Parameters:    parameters,
		StackName:     &stack,
		Tags: []*cloudformation.Tag{ // Tags are propagated to every supported resource in the stack
			{Key: aws.String("Application"), Value: aws.String("Panther")},
			{Key: aws.String("PantherVersion"), Value: &pantherVersion},
			{Key: aws.String("Stack"), Value: &stack},
		},
	}

	contents := readFile(templateFile)
	if len(contents) <= maxTemplateSize {
		createInput.TemplateBody = aws.String(string(contents))
	}
	if len(contents) >= maxTemplateSize {
		upload, err := uploadFileToS3(awsSession, templateFile, bucket, filepath.Base(templateFile), nil)
		if err != nil {
			logger.Fatal(err)
		}
		createInput.TemplateURL = &upload.Location
	}

	logger.Infof("deploy: %s CloudFormation stack %s", changeSetType, stack)
	if _, err = client.CreateChangeSet(createInput); err != nil {
		logger.Fatalf("failed to create change set for stack %s: %v", stack, err)
	}

	// Wait for change set creation to finish
	describeInput := &cloudformation.DescribeChangeSetInput{
		ChangeSetName: createInput.ChangeSetName,
		StackName:     &stack,
	}
	prevStatus := ""
	for start := time.Now(); time.Since(start) < pollTimeout; {
		response, err := client.DescribeChangeSet(describeInput)
		if err != nil {
			logger.Fatalf("failed to describe change set %s for stack %s: %v",
				*createInput.ChangeSetName, stack, err)
		}

		status := aws.StringValue(response.Status)
		reason := aws.StringValue(response.StatusReason)
		if status == "FAILED" && (strings.HasPrefix(reason, "The submitted information didn't contain changes") ||
			strings.HasPrefix(reason, "No updates are to be performed")) {

			logger.Debugf("deploy: stack %s is already up to date", stack)
			_, err := client.DeleteChangeSet(&cloudformation.DeleteChangeSetInput{
				ChangeSetName: createInput.ChangeSetName,
				StackName:     &stack,
			})
			if err != nil {
				logger.Warnf("failed to delete change set %s for stack %s: %v",
					*createInput.ChangeSetName, stack, err)
			}

			// No changes - return the stack outputs we got earlier
			return nil, flattenStackOutputs(stackDetail)
		}

		if status != prevStatus {
			logger.Debugf("deploy: CreateChangeSet for stack %s is now %s", stack, status)
			prevStatus = status
		}

		switch status {
		case "CREATE_COMPLETE":
			return createInput.ChangeSetName, nil // success!
		case "FAILED":
			logger.Fatalf("create change set for stack %s failed: %s", stack, reason)
		default:
			time.Sleep(pollInterval)
		}
	}

	logger.Fatalf("create change set for stack %s failed: timeout %s", stack, pollTimeout)
	return nil, nil // execution will never reach here
}

// Execute a change set, blocking until the stack has finished updating and returning its outputs.
func executeChangeSet(client *cloudformation.CloudFormation, changeSet *string, stack string) map[string]string {
	_, err := client.ExecuteChangeSet(&cloudformation.ExecuteChangeSetInput{
		ChangeSetName: changeSet,
		StackName:     &stack,
	})
	if err != nil {
		logger.Fatalf("failed to deploy stack %s: %v", stack, err)
	}

	// Wait for change set to finish.
	input := &cloudformation.DescribeStacksInput{StackName: &stack}
	prevStatus := ""
	for start := time.Now(); time.Since(start) < pollTimeout; {
		response, err := client.DescribeStacks(input)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ExpiredToken" {
				logger.Fatal("deploy: security token expired; " +
					"redeploy with fresh credentials to pick up where you left off. " +
					"CloudFormation is still running in your AWS account, see https://console.aws.amazon.com/cloudformation")
			}
			logger.Fatalf("failed to describe stack %s: %v", stack, err)
		}

		status := *response.Stacks[0].StackStatus
		if status != prevStatus {
			logger.Debugf("deploy: ExecuteChangeSet for stack %s is now %s", stack, status)
			prevStatus = status
		}

		if status == "CREATE_COMPLETE" || status == "UPDATE_COMPLETE" {
			return flattenStackOutputs(response) // success!
		} else if strings.Contains(status, "IN_PROGRESS") {
			// TODO - show progress of nested stacks (e.g. % updated)
			time.Sleep(pollInterval)
		} else {
			logger.Fatalf("execute change set for stack %s is %s: %s",
				stack, status, aws.StringValue(response.Stacks[0].StackStatusReason))
		}
	}

	logger.Fatalf("execute change set for stack %s failed: timeout %s", stack, pollTimeout)
	return nil // execution will never reach here
}
