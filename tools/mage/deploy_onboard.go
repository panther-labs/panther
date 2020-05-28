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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
)

const (
	// CloudSec IAM Roles, DO NOT CHANGE! panther-cloudsec-iam.yml CF depends on these names
	realTimeEventStackSetURL             = "https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudwatch-events/v0.1.8/template.yml" // nolint:lll
	realTimeEventsStackSet               = "panther-real-time-events"
	realTimeEventsExecutionRoleName      = "PantherCloudFormationStackSetExecutionRole"
	realTimeEventsAdministrationRoleName = "PantherCloudFormationStackSetAdminRole"
	realTimeEventsQueueName              = "panther-aws-events-queue" // needs to match what is in aws_events_processor.yml
)

// onboard Panther to monitor Panther account
func deployOnboard(
	awsSession *session.Session,
	accountID string,
) error {
	// Where to put Python analysis set resource?
	//    1) Core (next to analysis-api)
	//          - problem: rules-engine and policy-engine must exist
	//    2) Onboard
	//          - problem: entire onboard stack is conditional

	return deployRealTimeStackSet(awsSession, accountID)
}

// see: https://docs.runpanther.io/policies/scanning/real-time-events
func deployRealTimeStackSet(awsSession *session.Session, pantherAccountID string) error {
	logger.Info("deploy: enabling real time infrastructure monitoring with Panther")
	cfClient := cloudformation.New(awsSession)

	alreadyExists := func(err error) bool {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudformation.ErrCodeNameAlreadyExistsException {
			return true
		}
		return false
	}

	stackSetInput := &cloudformation.CreateStackSetInput{
		StackSetName: aws.String(realTimeEventsStackSet),
		Tags: []*cloudformation.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("Panther"),
			},
		},
		TemplateURL:       aws.String(realTimeEventStackSetURL),
		ExecutionRoleName: aws.String(realTimeEventsExecutionRoleName + "-" + *awsSession.Config.Region),
		AdministrationRoleARN: aws.String("arn:aws:iam::" + pantherAccountID + ":role/" +
			realTimeEventsAdministrationRoleName + "-" + *awsSession.Config.Region),
		Parameters: []*cloudformation.Parameter{
			{
				ParameterKey:   aws.String("MasterAccountId"),
				ParameterValue: aws.String(pantherAccountID),
			},
			{
				ParameterKey:   aws.String("QueueArn"),
				ParameterValue: aws.String("arn:aws:sqs:" + *awsSession.Config.Region + ":" + pantherAccountID + ":" + realTimeEventsQueueName),
			},
		},
	}
	_, err := cfClient.CreateStackSet(stackSetInput)
	if err != nil && !alreadyExists(err) {
		return fmt.Errorf("error creating real time stack set: %v", err)
	}

	stackSetInstancesInput := &cloudformation.CreateStackInstancesInput{
		Accounts: []*string{
			aws.String(pantherAccountID),
		},
		OperationPreferences: &cloudformation.StackSetOperationPreferences{
			FailureToleranceCount: aws.Int64(0),
			MaxConcurrentCount:    aws.Int64(1),
		},
		Regions:      []*string{awsSession.Config.Region},
		StackSetName: aws.String(realTimeEventsStackSet),
	}
	_, err = cfClient.CreateStackInstances(stackSetInstancesInput)
	if err != nil && !alreadyExists(err) {
		return fmt.Errorf("error creating real time stack instance: %v", err)
	}

	return nil
}
