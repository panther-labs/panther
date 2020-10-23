// Package awscfn contains helper functions that query/manipulate AWS Cloudformation stacks
package awscfn

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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"go.uber.org/zap"
)

// FlattenStackOutputs flatten CloudFormation stack outputs into a string map.
func FlattenStackOutputs(stack *cloudformation.Stack) map[string]string {
	result := make(map[string]string, len(stack.Outputs))
	for _, output := range stack.Outputs {
		result[*output.OutputKey] = *output.OutputValue
	}
	return result
}

func WaitForStackCreate(client *cloudformation.CloudFormation, logger *zap.SugaredLogger, stackName string,
	pollInterval time.Duration) (*cloudformation.Stack, error) {

	return WaitForStack(client, logger, stackName, cloudformation.StackStatusCreateComplete, pollInterval,
		cloudformation.StackStatusCreateInProgress)
}

func WaitForStackUpdate(client *cloudformation.CloudFormation, logger *zap.SugaredLogger, stackName string,
	pollInterval time.Duration) (*cloudformation.Stack, error) {

	return WaitForStack(client, logger, stackName, cloudformation.StackStatusUpdateComplete, pollInterval,
		cloudformation.StackStatusUpdateInProgress, cloudformation.StackStatusUpdateCompleteCleanupInProgress)
}

// Trigger stack deletion and wait for it to finish.
func DeleteStack(client *cloudformation.CloudFormation, logger *zap.SugaredLogger, stackName string, pollInterval time.Duration) error {
	if _, err := client.DeleteStack(&cloudformation.DeleteStackInput{StackName: &stackName}); err != nil {
		return err
	}

	_, err := WaitForStackDelete(client, logger, stackName, pollInterval)
	return err
}

func WaitForStackDelete(client *cloudformation.CloudFormation, logger *zap.SugaredLogger, stackName string,
	pollInterval time.Duration) (*cloudformation.Stack, error) {

	return WaitForStack(client, logger, stackName, cloudformation.StackStatusDeleteComplete, pollInterval,
		cloudformation.StackStatusDeleteInProgress)
}

// Wait for the stack to reach a terminal status and then return its details.
//
// 1) Keep waiting while stack status is inProgress
// 2) If stack status is successStatus, return stack details
// 3) If stack status is neither success nor inProgress, log failing resources and return an error
//
// This allows us to report errors to the user immediately, e.g. an "UPDATE_ROLLBACK_IN_PROGRESS"
// is considered a failed update - we don't have to wait until the stack is finished before finding
// and logging the errors.
//
// successStatus and inProgress can be omitted to wait for any terminal status.
//
// If the stack does not exist, we report its status as DELETE_COMPLETE
func WaitForStack(client *cloudformation.CloudFormation, logger *zap.SugaredLogger, stackName, successStatus string,
	pollInterval time.Duration, inProgress ...string) (*cloudformation.Stack, error) {

	// See all stack status codes and exactly what they mean here:
	// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-describing-stacks.html

	var allowedInProgress map[string]struct{}
	if len(inProgress) > 0 {
		allowedInProgress = make(map[string]struct{}, len(inProgress))
		for _, state := range inProgress {
			allowedInProgress[state] = struct{}{}
		}
	} else {
		// All IN_PROGRESS states are allowed with the exception of REVIEW_IN_PROGRESS.
		//
		// REVIEW_IN_PROGRESS means the stack doesn't actually exist yet;
		// there is a change set that was created but never applied - we would be waiting forever.
		allowedInProgress = map[string]struct{}{
			cloudformation.StackStatusCreateInProgress:                        {},
			cloudformation.StackStatusDeleteInProgress:                        {},
			cloudformation.StackStatusRollbackInProgress:                      {},
			cloudformation.StackStatusUpdateCompleteCleanupInProgress:         {},
			cloudformation.StackStatusUpdateInProgress:                        {},
			cloudformation.StackStatusUpdateRollbackCompleteCleanupInProgress: {},
			cloudformation.StackStatusUpdateRollbackInProgress:                {},
			cloudformation.StackStatusImportInProgress:                        {},
			cloudformation.StackStatusImportRollbackInProgress:                {},
		}
	}

	var stack *cloudformation.Stack
	start := time.Now()
	lastUserMessage := start

	// Wait until the stack is no longer in an expected IN_PROGRESS state
	for {
		detail, err := client.DescribeStacks(&cloudformation.DescribeStacksInput{StackName: &stackName})
		if ErrStackDoesNotExist(err) {
			// Special case - a deleted stack won't show up when describing stacks by name
			stack = &cloudformation.Stack{StackName: &stackName, StackStatus: aws.String(cloudformation.StackStatusDeleteComplete)}
			break
		}

		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ExpiredToken" {
				return nil, fmt.Errorf("%s: security token expired; "+
					"run again with fresh credentials to pick up where you left off. "+
					"CloudFormation is still running in your AWS account, "+
					"see https://console.aws.amazon.com/cloudformation", stackName)
			}

			return nil, fmt.Errorf("failed to describe stack %s: %v", stackName, err)
		}

		stack = detail.Stacks[0]
		if _, inSet := allowedInProgress[*stack.StackStatus]; !inSet {
			break
		}

		// Show the stack status occasionally
		if successStatus == "" && lastUserMessage == start {
			// If we just started and the caller wants the stack to be in any terminal state,
			// this is a standard deploy - let the user know what we're waiting on.
			logger.Warnf("stack %s was already %s, waiting for it to finish", stackName, *stack.StackStatus)
			lastUserMessage = time.Now()
		} else if time.Since(lastUserMessage) > 2*time.Minute {
			// Show progress every few minutes so it doesn't look stuck
			logger.Infof("    ... %s is still %s (%s)", stackName, *stack.StackStatus,
				time.Since(start).Round(time.Second).String())
			lastUserMessage = time.Now()
		}

		time.Sleep(pollInterval)
	}

	// Done waiting
	if successStatus == "" || *stack.StackStatus == successStatus {
		return stack, nil
	}

	// Error - stack entered an invalid state
	LogResourceFailures(client, logger, &stackName, start)
	return nil, errors.New(*stack.StackStatus)
}

// Returns true if the given error is from describing a stack that doesn't exist.
func ErrStackDoesNotExist(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ValidationError" &&
		strings.Contains(awsErr.Message(), "does not exist") {

		return true
	}
	return false
}

// Log failed resources from the stack's event history.
//
// Use this after a stack create/update/delete fails to understand why the stack failed.
// Events from nested stacks which failed are enumerated as well.
func LogResourceFailures(client *cloudformation.CloudFormation, logger *zap.SugaredLogger, stackID *string, start time.Time) {
	input := &cloudformation.DescribeStackEventsInput{StackName: stackID}
	failedStatus := map[string]struct{}{
		cloudformation.ResourceStatusCreateFailed: {},
		cloudformation.ResourceStatusDeleteFailed: {},
		cloudformation.ResourceStatusUpdateFailed: {},
	}

	// Events are listed in reverse chronological order (most recent first)
	err := client.DescribeStackEventsPages(input, func(page *cloudformation.DescribeStackEventsOutput, isLast bool) bool {
		for _, event := range page.StackEvents {
			if (*event.Timestamp).Before(start) {
				// Found the beginning of the events we care about: stop here
				return false
			}

			status := *event.ResourceStatus
			if _, ok := failedStatus[status]; !ok {
				continue
			}

			resourceType := *event.ResourceType
			logicalID, physicalID := *event.LogicalResourceId, *event.PhysicalResourceId
			if resourceType == "AWS::CloudFormation::Stack" && logicalID != *stackID && physicalID != *stackID {
				// If a nested stack failed, describe those events as well
				LogResourceFailures(client, logger, event.PhysicalResourceId, start)
			}

			reason := aws.StringValue(event.ResourceStatusReason)
			if reason == "Resource update cancelled" || reason == "Resource creation cancelled" {
				continue
			}

			stackName := *stackID
			if strings.HasPrefix(stackName, "arn") {
				// The stackID is the full arn (i.e. a nested stack), for example:
				//   arn:aws:cloudformation:us-west-2:111122223333:stack/panther-cw-alarms-BootstrapAlarms-1JFSJVDA48SZI/uuid
				// Pull out just the stack name to make it easier to read
				stackName = strings.Split(stackName, "/")[1]
			}
			logger.Errorf("stack %s: %s %s %s: %s", stackName, resourceType, logicalID, status, reason)
		}

		return true // keep paging
	})

	if err != nil {
		logger.Warnf("failed to list stack events for %s: %v", *stackID, err)
	}
}

// Returns combined outputs from one or more stacks. Treats errors as fatal.
func StackOutputs(client *cloudformation.CloudFormation, stacks ...string) (map[string]string, error) {
	result := make(map[string]string)

	for _, stack := range stacks {
		input := &cloudformation.DescribeStacksInput{StackName: aws.String(stack)}
		response, err := client.DescribeStacks(input)
		if err != nil {
			return nil, err
		}

		for k, v := range FlattenStackOutputs(response.Stacks[0]) {
			result[k] = v
		}
	}

	return result, nil
}

// StackTag returns the tag value for specified tag key for the given stack, will be blank if the stack or tag does not exist.
func StackTag(client *cloudformation.CloudFormation, tagKey, stack string) (string, error) {
	response, err := client.DescribeStacks(&cloudformation.DescribeStacksInput{StackName: &stack})
	if err != nil {
		if ErrStackDoesNotExist(err) {
			return "", nil
		}
		return "", err
	}

	for _, tag := range response.Stacks[0].Tags {
		if aws.StringValue(tag.Key) == tagKey {
			return aws.StringValue(tag.Value), nil
		}
	}

	return "", nil
}
