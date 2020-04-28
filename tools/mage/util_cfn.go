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
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"

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

// Summary of a CloudFormation resource and its parent stack
type cfnResource struct {
	Resource *cfn.StackResourceSummary
	Stack    *cfn.Stack
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
func waitForStack(client *cfn.CloudFormation, stackName, successStatus string, inProgress ...string) (*cfn.Stack, error) {
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
			cfn.StackStatusCreateInProgress:                        {},
			cfn.StackStatusDeleteInProgress:                        {},
			cfn.StackStatusRollbackInProgress:                      {},
			cfn.StackStatusUpdateCompleteCleanupInProgress:         {},
			cfn.StackStatusUpdateInProgress:                        {},
			cfn.StackStatusUpdateRollbackCompleteCleanupInProgress: {},
			cfn.StackStatusUpdateRollbackInProgress:                {},
			cfn.StackStatusImportInProgress:                        {},
			cfn.StackStatusImportRollbackInProgress:                {},
		}
	}

	var stack *cfn.Stack
	start := time.Now()
	lastUserMessage := start

	// Wait until the stack is no longer in an expected IN_PROGRESS state
	for {
		detail, err := client.DescribeStacks(&cfn.DescribeStacksInput{StackName: &stackName})
		if errStackDoesNotExist(err) {
			// Special case - a deleted stack won't show up when describing stacks by name
			stack = &cfn.Stack{StackName: &stackName, StackStatus: aws.String(cfn.StackStatusDeleteComplete)}
			break
		}

		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ExpiredToken" {
				return nil, fmt.Errorf("deploy: %s: security token expired; "+
					"redeploy with fresh credentials to pick up where you left off. "+
					"CloudFormation is still running in your AWS account, "+
					"see https://console.aws.amazon.com/cloudformation", stackName)
			}

			return nil, fmt.Errorf("failed to describe stack %s: %v", stackName, err)
		}

		stack = detail.Stacks[0]
		if _, inSet := allowedInProgress[*stack.StackStatus]; !inSet {
			break
		}

		// Show the stack status every few minutes
		if time.Since(lastUserMessage) > 2*time.Minute {
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
	logResourceFailures(client, &stackName, start)
	return nil, errors.New(*stack.StackStatus)
}

func waitForStackCreate(client *cfn.CloudFormation, stackName string) (*cfn.Stack, error) {
	return waitForStack(client, stackName, cfn.StackStatusCreateComplete, cfn.StackStatusCreateInProgress)
}

func waitForStackDelete(client *cfn.CloudFormation, stackName string) (*cfn.Stack, error) {
	return waitForStack(client, stackName, cfn.StackStatusDeleteComplete, cfn.StackStatusDeleteInProgress)
}

func waitForStackUpdate(client *cfn.CloudFormation, stackName string) (*cfn.Stack, error) {
	return waitForStack(client, stackName, cfn.StackStatusUpdateComplete,
		cfn.StackStatusUpdateInProgress, cfn.StackStatusUpdateCompleteCleanupInProgress)
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

// List resources for a single Panther stack, recursively enumerating nested stacks as well.
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

// Log failed resources from the stack's event history.
//
// Use this after a stack create/update/delete fails to understand why the stack failed.
// Events from nested stacks which failed are enumerated as well.
func logResourceFailures(client *cfn.CloudFormation, stackID *string, start time.Time) {
	input := &cfn.DescribeStackEventsInput{StackName: stackID}
	failedStatus := map[string]struct{}{
		cfn.ResourceStatusCreateFailed: {},
		cfn.ResourceStatusDeleteFailed: {},
		cfn.ResourceStatusUpdateFailed: {},
	}

	// Events are listed in reverse chronological order (most recent first)
	err := client.DescribeStackEventsPages(input, func(page *cfn.DescribeStackEventsOutput, isLast bool) bool {
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
				logResourceFailures(client, event.PhysicalResourceId, start)
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
