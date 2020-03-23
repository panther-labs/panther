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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
)

var allStacks = []string{backendStack, bucketStack, monitoringStack, frontendStack, databasesStack, onboardStack}

// Summary of a CloudFormation resource and the stack its contained in
type cfnResource struct {
	Resource *cfn.StackResourceSummary
	Stack    *cfn.Stack
}

// Get CloudFormation stack outputs as a map.
func getStackOutputs(awsSession *session.Session, name string) (map[string]string, error) {
	cfnClient := cfn.New(awsSession)
	input := &cfn.DescribeStacksInput{StackName: &name}
	response, err := cfnClient.DescribeStacks(input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe stack %s: %v", name, err)
	}

	return flattenStackOutputs(response), nil
}

// Flatten CloudFormation stack outputs into a string map.
func flattenStackOutputs(detail *cfn.DescribeStacksOutput) map[string]string {
	outputs := detail.Stacks[0].Outputs
	result := make(map[string]string, len(outputs))
	for _, output := range outputs {
		result[*output.OutputKey] = *output.OutputValue
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
		if isStackNotExistsError(*stackID, err) {
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

// Returns true if the error is indication that the specified CFN stack doesn't exist false otherwise.
func isStackNotExistsError(stackID string, err error) bool {
	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ValidationError" &&
		strings.TrimSpace(awsErr.Message()) == fmt.Sprintf("Stack with id %s does not exist", stackID) {

		return true
	}
	return false
}
