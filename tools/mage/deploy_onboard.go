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
	"github.com/google/uuid"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

const (
	onboardStack    = "panther-app-onboard"
	onboardTemplate = "deployments/onboard.yml"

	realTimeStackSetURL = "https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudwatch-events/latest/template.yml" // nolint:lll
)

// onboard Panther to monitor Panther account
func deployOnboard(awsSession *session.Session, bucket string, backendOutputs map[string]string) {
	params := map[string]string{} // currently none
	deployTemplate(awsSession, onboardTemplate, bucket, onboardStack, params)

	registerPantherAccount(awsSession, backendOutputs["AWSAccountId"])

	deployRealTimeStackSet(awsSession, backendOutputs["AWSAccountId"])
}

func registerPantherAccount(awsSession *session.Session, pantherAccountID string) {
	var apiInput = struct {
		PutIntegration *models.PutIntegrationInput
	}{
		&models.PutIntegrationInput{
			Integrations: []*models.PutIntegrationSettings{
				{
					AWSAccountID:     aws.String(pantherAccountID),
					IntegrationLabel: aws.String("Panther Account"),
					IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
					ScanEnabled:      aws.Bool(true),
					ScanIntervalMins: aws.Int(1440),
					UserID:           aws.String(uuid.New().String()), // generate a uuid4
				},
			},
		},
	}
	if err := invokeLambda(awsSession, "panther-source-api", apiInput, nil); err != nil {
		logger.Errorf("error calling lambda to register account: %v", err)
		return
	}
}

// see: https://docs.runpanther.io/policies/scanning/real-time-events
func deployRealTimeStackSet(awsSession *session.Session, pantherAccountID string) {
	cfClient := cloudformation.New(awsSession)

	const (
		stackSetName           = "panther-real-time-events"
		executionRoleName      = "PantherCloudFormationStackSetExecutionRole"
		administrationRoleName = "PantherCloudFormationStackSetAdminRole"
	)

	alreadyExists := func(err error) bool {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudformation.ErrCodeNameAlreadyExistsException {
			return true
		}
		return false
	}

	stackSetInput := &cloudformation.CreateStackSetInput{
		StackSetName:          aws.String(stackSetName),
		TemplateURL:           aws.String(realTimeStackSetURL),
		ExecutionRoleName:     aws.String(executionRoleName),
		AdministrationRoleARN: aws.String("arn:aws:iam::" + pantherAccountID + ":role/" + administrationRoleName),
		Parameters: []*cloudformation.Parameter{
			{
				ParameterKey:   aws.String("MasterAccountId"),
				ParameterValue: aws.String(pantherAccountID),
			},
			{
				ParameterKey:   aws.String("QueueArn"),
				ParameterValue: aws.String("arn:aws:sqs:" + *awsSession.Config.Region + ":" + pantherAccountID + ":panther-aws-events-queue"),
			},
		},
	}
	_, err := cfClient.CreateStackSet(stackSetInput)
	if err != nil && !alreadyExists(err) {
		logger.Errorf("error creating real time stack set: %v", err)
		return
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
		StackSetName: aws.String(stackSetName),
	}
	_, err = cfClient.CreateStackInstances(stackSetInstancesInput)
	if err != nil && !alreadyExists(err) {
		logger.Errorf("error creating real time stack instance: %v", err)
		return
	}
}
