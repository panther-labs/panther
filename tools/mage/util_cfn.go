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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	jsoniter "github.com/json-iterator/go"
	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/tools/config"
)

var allStacks = []string{
	bootstrapStack,
	gatewayStack,

	alarmsStack,
	appsyncStack,
	cloudsecStack,
	coreStack,
	dashboardStack,
	frontendStack,
	glueStack,
	logAnalysisStack,
	metricFilterStack,
	onboardStack,
}

// CloudFormation stacks in one of these states have changes in progress.
var inProgressStackStatus = map[string]struct{}{
	cfn.StackStatusCreateInProgress:                        {},
	cfn.StackStatusDeleteInProgress:                        {},
	cfn.StackStatusReviewInProgress:                        {},
	cfn.StackStatusRollbackInProgress:                      {},
	cfn.StackStatusUpdateCompleteCleanupInProgress:         {},
	cfn.StackStatusUpdateInProgress:                        {},
	cfn.StackStatusUpdateRollbackCompleteCleanupInProgress: {},
	cfn.StackStatusUpdateRollbackInProgress:                {},
	cfn.StackStatusImportInProgress:                        {},
	cfn.StackStatusImportRollbackInProgress:                {},
}

// Cloudformation stacks in one of these states will not change until a user takes action.
var terminalStackStatus = map[string]struct{}{
	cfn.StackStatusCreateComplete:         {},
	cfn.StackStatusCreateFailed:           {},
	cfn.StackStatusDeleteComplete:         {},
	cfn.StackStatusDeleteFailed:           {},
	cfn.StackStatusImportComplete:         {},
	cfn.StackStatusImportRollbackComplete: {},
	cfn.StackStatusImportRollbackFailed:   {},
	cfn.StackStatusRollbackComplete:       {},
	cfn.StackStatusRollbackFailed:         {},
	cfn.StackStatusUpdateComplete:         {},
	cfn.StackStatusUpdateRollbackComplete: {},
	cfn.StackStatusUpdateRollbackFailed:   {},
}

// Summary of a CloudFormation resource and the stack its contained in
type cfnResource struct {
	Resource *cfn.StackResourceSummary
	Stack    *cfn.Stack
}

// Parse a CloudFormation template, returning a json map.
//
// Short-form functions like "!If" and "!Sub" will be replaced with "Fn::" objects.
func parseCfnTemplate(path string) (map[string]interface{}, error) {
	if err := os.MkdirAll("out", 0755); err != nil {
		return nil, err
	}

	// The Go yaml parser doesn't understand short-form functions.
	// So we first use cfn-flip to flip .yml to .json
	if strings.ToLower(filepath.Ext(path)) != ".json" {
		jsonPath := filepath.Join("out", filepath.Base(path)+".json")
		if err := sh.Run(filepath.Join(pythonVirtualEnvPath, "bin", "cfn-flip"), "-j", path, jsonPath); err != nil {
			return nil, fmt.Errorf("failed to flip %s to json: %v", path, err)
		}
		defer os.Remove(jsonPath)
		path = jsonPath
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", path, err)
	}

	var result map[string]interface{}
	return result, jsoniter.Unmarshal(contents, &result)
}

// Save the CloudFormation structure as a .yml file.
func writeCfnTemplate(cfn map[string]interface{}, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(path), err)
	}

	contents, err := yaml.Marshal(cfn)
	if err != nil {
		return fmt.Errorf("yaml marshal failed: %v", err)
	}

	return ioutil.WriteFile(path, contents, 0644)
}

// Flatten CloudFormation stack outputs into a string map.
func flattenStackOutputs(stack *cfn.Stack) map[string]string {
	result := make(map[string]string, len(stack.Outputs))
	for _, output := range stack.Outputs {
		result[*output.OutputKey] = *output.OutputValue
	}
	return result
}

// Return the list of Panther's CloudFormation files
func cfnFiles() []string {
	paths, err := filepath.Glob("deployments/*.yml")
	if err != nil {
		logger.Fatalf("failed to glob deployments: %v", err)
	}

	// Remove the config file
	var result []string
	for _, p := range paths {
		if p != config.Filepath {
			result = append(result, p)
		}
	}
	return result
}

// Traverse all Panther CFN resources (across all stacks) and apply the given handler.
func walkPantherStacks(client *cfn.CloudFormation, handler func(cfnResource)) error {
	logger.Info("scanning Panther CloudFormation stacks")
	for _, stack := range allStacks {
		if err := walkPantherStack(client, aws.String(stack), handler); err != nil {
			return err
		}
	}
	return nil
}

// Recursively list resources for a single Panther stack.
//
// The stackID can be the stack name or arn and the stack must be tagged with "Application:Panther"
func walkPantherStack(client *cfn.CloudFormation, stackID *string, handler func(cfnResource)) error {
	logger.Debugf("enumerating stack %s", *stackID)
	detail, err := client.DescribeStacks(&cfn.DescribeStacksInput{StackName: stackID})
	if err != nil {
		if errStackDoesNotExist(err) {
			logger.Debugf("stack %s does not exist", *stackID)
			return nil
		}

		return fmt.Errorf("failed to describe stack %s: %v", *stackID, err)
	}

	// Double-check the stack is tagged with Application:Panther
	stack := detail.Stacks[0]
	foundTag := false
	for _, tag := range stack.Tags {
		if aws.StringValue(tag.Key) == "Application" && aws.StringValue(tag.Value) == "Panther" {
			foundTag = true
			break
		}
	}

	if !foundTag {
		logger.Warnf("skipping stack %s: no 'Application=Panther' tag found", *stackID)
		return nil
	}

	// List stack resources
	input := &cfn.ListStackResourcesInput{StackName: stackID}
	var nestedErr error
	err = client.ListStackResourcesPages(input, func(page *cfn.ListStackResourcesOutput, isLast bool) bool {
		for _, summary := range page.StackResourceSummaries {
			handler(cfnResource{Resource: summary, Stack: stack})
			if aws.StringValue(summary.ResourceType) == "AWS::CloudFormation::Stack" &&
				aws.StringValue(summary.ResourceStatus) != cfn.ResourceStatusDeleteComplete {

				// Recurse into nested stack
				if nestedErr = walkPantherStack(client, summary.PhysicalResourceId, handler); nestedErr != nil {
					return false // stop paging, handle error outside closure
				}
			}
		}
		return true // keep paging
	})

	if err != nil {
		return fmt.Errorf("failed to list stack resources for %s: %v", *stackID, err)
	}
	if nestedErr != nil {
		return nestedErr
	}

	return nil
}

// Returns true if the given error is from describing a stack that doesn't exist.
func errStackDoesNotExist(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ValidationError" &&
		strings.Contains(awsErr.Message(), "does not exist") {

		return true
	}
	return false
}

// Return true if CF stack set exists
func stackSetExists(cfClient *cfn.CloudFormation, stackSetName string) (bool, error) {
	input := &cfn.DescribeStackSetInput{StackSetName: aws.String(stackSetName)}
	_, err := cfClient.DescribeStackSet(input)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "StackSetNotFoundException" {
			err = nil
		}
		return false, err
	}
	return true, nil
}

// Return true if CF stack set exists
func stackSetInstanceExists(cfClient *cfn.CloudFormation, stackSetName, account, region string) (bool, error) {
	input := &cfn.DescribeStackInstanceInput{
		StackSetName:         &stackSetName,
		StackInstanceAccount: &account,
		StackInstanceRegion:  &region,
	}
	_, err := cfClient.DescribeStackInstance(input)
	if err != nil {
		// need to also check for "StackSetNotFoundException" if the containing stack set does not exist
		if awsErr, ok := err.(awserr.Error); ok &&
			(awsErr.Code() == "StackInstanceNotFoundException" || awsErr.Code() == "StackSetNotFoundException") {

			err = nil
		}
		return false, err
	}
	return true, nil
}

// Returns stack status, outputs, and any error
func describeStack(cfClient *cfn.CloudFormation, stackName string) (string, map[string]string, error) {
	input := &cfn.DescribeStacksInput{StackName: &stackName}
	response, err := cfClient.DescribeStacks(input)
	if err != nil {
		return "", nil, err
	}

	return aws.StringValue(response.Stacks[0].StackStatus), flattenStackOutputs(response.Stacks[0]), nil
}
