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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

const (
	onboardStack    = "panther-app-onboard"
	onboardTemplate = "deployments/onboard.yml"

	realTimeEventStackSetURL             = "https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudwatch-events/latest/template.yml" // nolint:lll
	realTimeEventsStackSet               = "panther-real-time-events"
	realTimeEventsExecutionRoleName      = "PantherCloudFormationStackSetExecutionRole"
	realTimeEventsAdministrationRoleName = "PantherCloudFormationStackSetAdminRole"
	realTimeEventsQueueName              = "panther-aws-events-queue" // needs to match what is in aws_events_processor.yml
)

// onboard Panther to monitor Panther account
func deployOnboard(awsSession *session.Session, bucket string, backendOutputs map[string]string) {
	deployCloudSecRoles(awsSession, bucket)
	registerPantherAccount(awsSession, backendOutputs["AWSAccountId"]) // this MUST follow the CloudSec roles being deployed
	deployRealTimeStackSet(awsSession, backendOutputs["AWSAccountId"])
}

func deployCloudSecRoles(awsSession *session.Session, bucket string) {
	iamClient := iam.New(awsSession)
	auditRoleExists, err := roleExists(iamClient, auditRole)
	if err != nil {
		logger.Fatalf("error checking audit role name %s: %v", auditRole, err)
	}
	remediationRoleExists, err := roleExists(iamClient, remediationRole)
	if err != nil {
		logger.Fatalf("error checking remediation role name %s: %v", remediationRole, err)
	}
	adminRoleExists, err := roleExists(iamClient, realTimeEventsAdministrationRoleName)
	if err != nil {
		logger.Fatalf("error checking admin role name %s: %v", realTimeEventsAdministrationRoleName, err)
	}

	if !auditRoleExists && !remediationRoleExists && !adminRoleExists {
		logger.Info("deploy: creating iam roles for CloudSecurity")
		params := map[string]string{} // currently none
		deployTemplate(awsSession, onboardTemplate, bucket, onboardStack, params)
	} else {
		logger.Info("deploy: iam roles for CloudSecurity exist (not creating)")
	}
}

func registerPantherAccount(awsSession *session.Session, pantherAccountID string) {
	logger.Infof("deploy: registering account %s with Panther", pantherAccountID)
	apiInput := &models.LambdaInput{
		PutIntegration: &models.PutIntegrationInput{
			PutIntegrationSettings: models.PutIntegrationSettings{
				AWSAccountID:     aws.String(pantherAccountID),
				IntegrationLabel: aws.String("Panther Account"),
				IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
				ScanIntervalMins: aws.Int(1440),
				UserID:           aws.String(mageUserID),
			},
		},
	}
	if err := invokeLambda(awsSession, "panther-source-api", apiInput, nil); err != nil {
		logger.Fatalf("error calling lambda to register account: %v", err)
	}
}

// see: https://docs.runpanther.io/policies/scanning/real-time-events
func deployRealTimeStackSet(awsSession *session.Session, pantherAccountID string) {
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
		TemplateURL:           aws.String(realTimeEventStackSetURL),
		ExecutionRoleName:     aws.String(realTimeEventsExecutionRoleName),
		AdministrationRoleARN: aws.String("arn:aws:iam::" + pantherAccountID + ":role/" + realTimeEventsAdministrationRoleName),
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
		logger.Fatalf("error creating real time stack set: %v", err)
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
		logger.Fatalf("error creating real time stack instance: %v", err)
	}
}
