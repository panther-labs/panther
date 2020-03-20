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
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/tools/config"
)

const (
	cloudSecLabel      = "PantherCloudSecurity"
	logProcessingLabel = "PantherLogProcessing"

	onboardStack    = "panther-app-onboard"
	onboardTemplate = "deployments/onboard.yml"

	// CloudSec IAM Roles, DO NOT CHANGE! panther-compliance-iam.yml CF depends on these names
	auditRole       = "PantherAuditRole"
	remediationRole = "PantherRemediationRole"

	realTimeEventStackSetURL             = "https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudwatch-events/latest/template.yml" // nolint:lll
	realTimeEventsStackSet               = "panther-real-time-events"
	realTimeEventsExecutionRoleName      = "PantherCloudFormationStackSetExecutionRole"
	realTimeEventsAdministrationRoleName = "PantherCloudFormationStackSetAdminRole"
	realTimeEventsQueueName              = "panther-aws-events-queue" // needs to match what is in aws_events_processor.yml
)

// onboard Panther to monitor Panther account
func deployOnboard(awsSession *session.Session, settings *config.PantherConfig, bucketOutputs, backendOutputs map[string]string) {
	deployOnboardTemplate(awsSession, settings, bucketOutputs)
	registerPantherAccount(awsSession, bucketOutputs, backendOutputs) // this MUST follow the CloudSec roles being deployed
	deployRealTimeStackSet(awsSession, backendOutputs["AWSAccountId"])
}

func deployOnboardTemplate(awsSession *session.Session, settings *config.PantherConfig, bucketOutputs map[string]string) {
	if settings.OnboardParameterValues.EnableCloudTrail {
		logger.Info("deploy: enabling CloudTrail in Panther account (see panther_config.yml)")
	}
	if settings.OnboardParameterValues.EnableGuardDuty {
		logger.Info("deploy: enabling Guard Duty in Panther account (see panther_config.yml)")
	}

	// GD is account wide, not regional. Test if some other region has already enabled GD.
	if guardDutyEnabledOutsidePanther(awsSession, settings) {
		logger.Info("deploy: Guard Duty is already enabled for this account (not by Panther)")
		settings.OnboardParameterValues.EnableGuardDuty = false
	}

	params := map[string]string{
		"AuditLogsBucket":        bucketOutputs["AuditLogsBucket"],
		"EnableCloudTrail":       strconv.FormatBool(settings.OnboardParameterValues.EnableCloudTrail),
		"EnableGuardDuty":        strconv.FormatBool(settings.OnboardParameterValues.EnableGuardDuty),
		"LogProcessingRoleLabel": logProcessingLabel,
	}
	onboardOutputs := deployTemplate(awsSession, onboardTemplate, bucketOutputs["SourceBucketName"], onboardStack, params)
	configureLogProcessingUsingAPIs(awsSession, settings, bucketOutputs, onboardOutputs)
}

func registerPantherAccount(awsSession *session.Session, bucketOutputs, backendOutputs map[string]string) {
	logger.Infof("deploy: registering account %s with Panther for monitoring", backendOutputs["AWSAccountId"])

	// cloud sec
	var cloudSecInput = struct {
		PutIntegration *models.PutIntegrationInput
	}{
		&models.PutIntegrationInput{
			PutIntegrationSettings: models.PutIntegrationSettings{
				AWSAccountID:     aws.String(backendOutputs["AWSAccountId"]),
				IntegrationLabel: aws.String(cloudSecLabel),
				IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
				ScanIntervalMins: aws.Int(1440),
				UserID:           aws.String(mageUserID),
			},
		},
	}
	if err := invokeLambda(awsSession, "panther-source-api", cloudSecInput, nil); err != nil {
		logger.Fatalf("error calling lambda to register account for cloud security: %v", err)
	}

	// log processing
	var logProcessingInput = struct {
		PutIntegration *models.PutIntegrationInput
	}{
		&models.PutIntegrationInput{
			PutIntegrationSettings: models.PutIntegrationSettings{
				AWSAccountID:     aws.String(backendOutputs["AWSAccountId"]),
				IntegrationLabel: aws.String(logProcessingLabel),
				IntegrationType:  aws.String(models.IntegrationTypeAWS3),
				UserID:           aws.String(mageUserID),
				S3Bucket:         aws.String(bucketOutputs["AuditLogsBucket"]),
			},
		},
	}
	if err := invokeLambda(awsSession, "panther-source-api", logProcessingInput, nil); err != nil {
		logger.Fatalf("error calling lambda to register account for log processing: %v", err)
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

func configureLogProcessingUsingAPIs(awsSession *session.Session, settings *config.PantherConfig,
	bucketOutputs, onboardOutputs map[string]string) {

	// currently GuardDuty does not support this in CF
	configureLogProcessingGuardDuty(awsSession, settings, bucketOutputs, onboardOutputs)

	// configure notifications on the audit bucket, cannot be done via CF
	topicArn := onboardOutputs["LogProcessingTopicArn"]
	logBucket := bucketOutputs["AuditLogsBucket"]
	s3Client := s3.New(awsSession)
	input := &s3.PutBucketNotificationConfigurationInput{
		Bucket: aws.String(logBucket),
		NotificationConfiguration: &s3.NotificationConfiguration{
			TopicConfigurations: []*s3.TopicConfiguration{
				{
					Events: []*string{
						aws.String(s3.EventS3ObjectCreated),
					},
					TopicArn: &topicArn,
				},
			},
		},
	}
	_, err := s3Client.PutBucketNotificationConfiguration(input)
	if err != nil {
		logger.Fatalf("failed to add s3 notifications to %s from %s: %v", logBucket, topicArn, err)
	}
}

func guardDutyEnabledOutsidePanther(awsSession *session.Session, settings *config.PantherConfig) bool {
	if !settings.OnboardParameterValues.EnableGuardDuty {
		return false
	}
	gdClient := guardduty.New(awsSession)
	input := &guardduty.ListDetectorsInput{}
	output, err := gdClient.ListDetectors(input)
	if err != nil {
		logger.Fatalf("deploy: unable to check guard duty: %v", err)
	}
	if len(output.DetectorIds) != 1 {
		return false // we only make 1
	}
	// we need to check that it is THIS region's stack the enabled it
	_, onboardOutput, err := describeStack(cloudformation.New(awsSession), onboardStack)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudformation.ErrCodeStackSetNotFoundException {
			return true // not deployed anything yet in this region BUT it is enabled, must be another deployment
		}
		logger.Fatalf("deploy: cannot check stack %s: %v", onboardStack, err)
	}
	// if my stack has no reference, then it must have been enabled by another deployment
	return len(onboardOutput) == 0 || onboardOutput["GuardDutyDetectorId"] == ""
}

func configureLogProcessingGuardDuty(awsSession *session.Session, settings *config.PantherConfig,
	bucketOutputs, onboardOutputs map[string]string) {

	if !settings.OnboardParameterValues.EnableGuardDuty {
		return
	}
	gdClient := guardduty.New(awsSession)
	publishInput := &guardduty.CreatePublishingDestinationInput{
		DetectorId:      aws.String(onboardOutputs["GuardDutyDetectorId"]),
		DestinationType: aws.String("S3"),
		DestinationProperties: &guardduty.DestinationProperties{
			DestinationArn: aws.String("arn:aws:s3:::" + bucketOutputs["AuditLogsBucket"]),
			KmsKeyArn:      aws.String(onboardOutputs["GuardDutyKmsKeyArn"]),
		},
	}
	_, err := gdClient.CreatePublishingDestination(publishInput)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		logger.Fatalf("failed to configure Guard Duty detector %s to use bucket %s with kms key %s: %v",
			onboardOutputs["GuardDutyDetectorId"], bucketOutputs["AuditLogsBucket"],
			onboardOutputs["GuardDutyKmsKeyArn"], err)
	}
}
