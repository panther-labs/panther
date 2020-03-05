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

var allStacks = []string{backendStack, bucketStack, monitoringStack, frontendStack, databasesStack}

// Summary of a CloudFormation resource and the stack its contained in
type cfnResource struct {
	*cfn.StackResourceSummary
	*cfn.Stack
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

// Return all Panther CloudFormation resources (across all stacks) which match the given filter (optional).
func findStackResources(client *cfn.CloudFormation, filter func(*cfn.StackResourceSummary) bool) ([]cfnResource, error) {
	var result []cfnResource

	for _, stack := range allStacks {
		resources, err := stackResources(client, &stack, filter)
		if err != nil {
			return nil, err
		}
		result = append(result, resources...)
	}

	return result, nil
}

// Recursively list resources for a single stack.
//
// The stackID can be a name or the full unique arn
func stackResources(client *cfn.CloudFormation, stackID *string, filter func(*cfn.StackResourceSummary) bool) ([]cfnResource, error) {
	logger.Debugf("enumerating stack %s", *stackID)
	detail, err := client.DescribeStacks(&cfn.DescribeStacksInput{StackName: stackID})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ValidationError" &&
			strings.TrimSpace(awsErr.Message()) == fmt.Sprintf("Stack with id %s does not exist", *stackID) {

			logger.Debugf("stack %s does not exist", *stackID)
			return nil, nil
		}

		return nil, fmt.Errorf("failed to describe stack %s: %v", *stackID, err)
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
		return nil, nil
	}

	// List matching resources
	var result []cfnResource
	input := &cfn.ListStackResourcesInput{StackName: stackID}
	var nestedErr error
	err = client.ListStackResourcesPages(input, func(page *cfn.ListStackResourcesOutput, isLast bool) bool {
		for _, summary := range page.StackResourceSummaries {
			if filter != nil && filter(summary) {
				result = append(result, cfnResource{StackResourceSummary: summary, Stack: stack})
			}

			if aws.StringValue(summary.ResourceType) == "AWS::CloudFormation::Stack" &&
				aws.StringValue(summary.ResourceStatus) != "DELETE_COMPLETE" {

				// Recurse into nested stack
				nested, err := stackResources(client, summary.PhysicalResourceId, filter)
				if err != nil {
					nestedErr = err
					return false // stop paging, handle error outside closure
				}
				result = append(result, nested...)
			}
		}
		return true // keep paging
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list stack resources for %s: %v", *stackID, err)
	}
	if nestedErr != nil {
		return nil, nestedErr
	}

	return result, nil
}
