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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
)

const (
	pollInterval = 5 * time.Second // How long to wait in between requests to the CloudFormation service
	pollTimeout  = time.Hour       // Give up if CreateChangeSet or ExecuteChangeSet takes longer than this
)

// Deploy a CloudFormation template.
//
// This is our own implementation of "cloudformation deploy" from the AWS CLI.
// Here we have more control over the output and waiters.
func deployTemplate(awsSession *session.Session, templateFile, stack string, params map[string]string) error {
	changeSet, err := createChangeSet(awsSession, templateFile, stack, params)
	if err != nil {
		return err
	}
	if changeSet == "" {
		return nil // nothing to do
	}
	return executeChangeSet(awsSession, changeSet, stack)
}

// Create a CloudFormation change set, returning its name.
//
// If there are no pending changes, the change set is deleted and a blank name is returned.
func createChangeSet(awsSession *session.Session, templateFile, stack string, params map[string]string) (string, error) {
	// Change set name - username + unix time (must be unique)
	changeSetName := fmt.Sprintf("panther-%d", time.Now().UnixNano())

	// Change set type - CREATE if a new stack otherwise UPDATE
	client := cloudformation.New(awsSession)
	response, err := client.DescribeStacks(&cloudformation.DescribeStacksInput{StackName: &stack})
	changeSetType := "CREATE"
	if err == nil && len(response.Stacks) > 0 {
		// Check if the previous deployment timed out and is still going, if so continue where that left off
		if strings.Contains(*response.Stacks[0].StackStatus, "IN_PROGRESS") {
			fmt.Printf("deploy: WARNING: %s already in state %s, resuming previous deployment\n", stack, *response.Stacks[0].StackStatus)
			return *response.Stacks[0].ChangeSetId, nil
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

	templateBody := readFile(templateFile)

	createInput := &cloudformation.CreateChangeSetInput{
		Capabilities: []*string{
			aws.String("CAPABILITY_AUTO_EXPAND"),
			aws.String("CAPABILITY_IAM"),
			aws.String("CAPABILITY_NAMED_IAM"),
		},
		ChangeSetName: &changeSetName,
		ChangeSetType: &changeSetType,
		Parameters:    parameters,
		StackName:     &stack,
		Tags: []*cloudformation.Tag{
			// Tags are propagated to every supported resource in the stack
			{
				Key:   aws.String("Application"),
				Value: aws.String("Panther"),
			},
		},
		TemplateBody: aws.String(string(templateBody)),
	}

	if _, err = client.CreateChangeSet(createInput); err != nil {
		return "", err
	}

	// Wait for change set creation to finish
	describeInput := &cloudformation.DescribeChangeSetInput{ChangeSetName: &changeSetName, StackName: &stack}
	prevStatus := ""
	for start := time.Now(); time.Since(start) < pollTimeout; {
		response, err := client.DescribeChangeSet(describeInput)
		if err != nil {
			return "", err
		}

		status := aws.StringValue(response.Status)
		reason := aws.StringValue(response.StatusReason)
		if status == "FAILED" && strings.HasPrefix(reason, "The submitted information didn't contain changes") {
			fmt.Printf("deploy: %s: no changes needed\n", stack)
			_, err := client.DeleteChangeSet(&cloudformation.DeleteChangeSetInput{
				ChangeSetName: &changeSetName,
				StackName:     &stack,
			})
			return "", err
		}

		if status != prevStatus {
			fmt.Printf("deploy: %s: CreateChangeSet: %s\n", stack, status)
			prevStatus = status
		}

		switch status {
		case "CREATE_COMPLETE":
			return changeSetName, nil // success!
		case "FAILED":
			return "", fmt.Errorf("create-change-set failed: " + reason)
		default:
			time.Sleep(pollInterval)
		}
	}

	return "", fmt.Errorf("create-change-set failed: timeout %s", pollTimeout)
}

func executeChangeSet(awsSession *session.Session, changeSet, stack string) error {
	client := cloudformation.New(awsSession)
	_, err := client.ExecuteChangeSet(&cloudformation.ExecuteChangeSetInput{
		ChangeSetName: &changeSet,
		StackName:     &stack,
	})
	if err != nil {
		return err
	}

	// Wait for change set to finish.
	// We build our own waiter to handle both update + create and to show status progress.
	input := &cloudformation.DescribeStacksInput{StackName: &stack}
	prevStatus := ""
	for start := time.Now(); time.Since(start) < pollTimeout; {
		response, err := client.DescribeStacks(input)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok {
				if awsErr.Code() == "ExpiredToken" {
					fmt.Printf("deploy: %s: ExecuteChangeSet: security token expired, exiting.\n"+
						"Re-executing the deploy command with fresh credentials will pick up where the previous deployment finished.\n", stack)
					return err
				}
			}
			return err
		}

		status := *response.Stacks[0].StackStatus
		if status != prevStatus {
			fmt.Printf("deploy: %s: ExecuteChangeSet: %s\n", stack, status)
			prevStatus = status
		}

		if status == "CREATE_COMPLETE" || status == "UPDATE_COMPLETE" {
			return nil // success!
		} else if strings.Contains(status, "IN_PROGRESS") {
			// TODO - show progress of nested stacks (e.g. % updated)
			time.Sleep(pollInterval)
		} else {
			return fmt.Errorf("execute-change-set failed: %s: %s",
				status, aws.StringValue(response.Stacks[0].StackStatusReason))
		}
	}

	return fmt.Errorf("execute-change-set failed: timeout %s", pollTimeout)
}
