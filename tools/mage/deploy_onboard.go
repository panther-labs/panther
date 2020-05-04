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
	cloudSecLabel      = "panther-account"
	logProcessingLabel = "panther-account" // this must be lowercase, no spaces to work correctly, see genLogProcessingLabel()

	// CloudSec IAM Roles, DO NOT CHANGE! panther-cloudsec-iam.yml CF depends on these names
	realTimeEventStackSetURL             = "https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudwatch-events/v0.1.8/template.yml" // nolint:lll
	realTimeEventsStackSet               = "panther-real-time-events"
	realTimeEventsExecutionRoleName      = "PantherCloudFormationStackSetExecutionRole"
	realTimeEventsAdministrationRoleName = "PantherCloudFormationStackSetAdminRole"
	realTimeEventsQueueName              = "panther-aws-events-queue" // needs to match what is in aws_events_processor.yml
)

// make label regionally unique
func genLogProcessingLabel(awsSession *session.Session) string {
	return logProcessingLabel + "-" + *awsSession.Config.Region
}

// onboard Panther to monitor Panther account
func deployOnboard(
	awsSession *session.Session,
	settings *config.PantherConfig,
	accountID string,
	bootstrapOutputs map[string]string,
) error {

	if err := deployOnboardTemplate(awsSession, settings, bootstrapOutputs); err != nil {
		return err
	}
	// registerPantherAccount MUST follow the CloudSec roles being deployed
	if err := registerPantherAccount(awsSession, settings, accountID, bootstrapOutputs["AuditLogsBucket"]); err != nil {
		return err
	}
	return deployRealTimeStackSet(awsSession, accountID)
}

func deployOnboardTemplate(awsSession *session.Session, settings *config.PantherConfig, bootstrapOutputs map[string]string) error {
	if settings.Setup.EnableCloudTrail {
		logger.Info("deploy: enabling CloudTrail in Panther account (see panther_config.yml)")
	}
	if settings.Setup.EnableGuardDuty {
		logger.Info("deploy: enabling Guard Duty in Panther account (see panther_config.yml)")
	}

	// GD is account wide, not regional. Test if some other region has already enabled GD.
	enabled, err := guardDutyEnabledOutsidePanther(awsSession, settings)
	if err != nil {
		return err
	}
	if enabled {
		logger.Info("deploy: Guard Duty is already enabled for this account (not by Panther)")
		settings.Setup.EnableGuardDuty = false
	}

	params := map[string]string{
		"AuditLogsBucket":        bootstrapOutputs["AuditLogsBucket"],
		"EnableCloudTrail":       strconv.FormatBool(settings.Setup.EnableCloudTrail),
		"EnableGuardDuty":        strconv.FormatBool(settings.Setup.EnableGuardDuty),
		"LogProcessingRoleLabel": genLogProcessingLabel(awsSession),
	}
	onboardOutputs, err := deployTemplate(awsSession, onboardTemplate, bootstrapOutputs["SourceBucket"], onboardStack, params)
	if err != nil {
		return err
	}
	return configureLogProcessingUsingAPIs(awsSession, settings, bootstrapOutputs["AuditLogsBucket"], onboardOutputs)
}

func registerPantherAccount(awsSession *session.Session, settings *config.PantherConfig, accountID, auditLogsBucket string) error {
	logger.Infof("deploy: registering account %s with Panther for monitoring", accountID)

	// avoid alarms/errors and check first if the integrations exist
	var listOutput []*models.SourceIntegration
	var listInput = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{},
	}
	if err := invokeLambda(awsSession, "panther-source-api", listInput, &listOutput); err != nil {
		return fmt.Errorf("error calling lambda to register account: %v", err)
	}

	// Check if registered. Technically this is not needed (PutIntegration will just fail) BUT when PutIntegration
	// fails this generates alarms. We don't want that so we check first and give a nice message.
	registerCloudSec, registerLogProcessing := true, true
	for _, integration := range listOutput {
		if aws.StringValue(integration.AWSAccountID) == accountID &&
			*integration.IntegrationType == models.IntegrationTypeAWSScan {

			logger.Infof("deploy: account %s is already registered for cloud security", accountID)
			registerCloudSec = false
		}
		if aws.StringValue(integration.AWSAccountID) == accountID &&
			*integration.IntegrationType == models.IntegrationTypeAWS3 &&
			*integration.IntegrationLabel == genLogProcessingLabel(awsSession) {

			logger.Infof("deploy: account %s is already registered for log processing", accountID)
			registerLogProcessing = false
		}
	}

	if registerCloudSec {
		input := &models.LambdaInput{
			PutIntegration: &models.PutIntegrationInput{
				PutIntegrationSettings: models.PutIntegrationSettings{
					AWSAccountID:       aws.String(accountID),
					IntegrationLabel:   aws.String(cloudSecLabel),
					IntegrationType:    aws.String(models.IntegrationTypeAWSScan),
					ScanIntervalMins:   aws.Int(1440),
					UserID:             aws.String(mageUserID),
					CWEEnabled:         aws.Bool(true),
					RemediationEnabled: aws.Bool(true),
				},
			},
		}
		if err := invokeLambda(awsSession, "panther-source-api", input, nil); err != nil &&
			!strings.Contains(err.Error(), "already onboarded") {

			return fmt.Errorf("error calling lambda to register account for cloud security: %v", err)
		}
		logger.Infof("deploy: account %s registered for cloud security", accountID)
	}

	if registerLogProcessing {
		logTypes := []string{"AWS.VPCFlow", "AWS.ALB"}
		if settings.Setup.EnableCloudTrail {
			logTypes = append(logTypes, "AWS.CloudTrail")
		}
		if settings.Setup.EnableGuardDuty {
			logTypes = append(logTypes, "AWS.GuardDuty")
		}
		if settings.Setup.EnableS3AccessLogs {
			logTypes = append(logTypes, "AWS.S3ServerAccess")
		}

		input := &models.LambdaInput{
			PutIntegration: &models.PutIntegrationInput{
				PutIntegrationSettings: models.PutIntegrationSettings{
					AWSAccountID:     aws.String(accountID),
					IntegrationLabel: aws.String(genLogProcessingLabel(awsSession)),
					IntegrationType:  aws.String(models.IntegrationTypeAWS3),
					UserID:           aws.String(mageUserID),
					S3Bucket:         aws.String(auditLogsBucket),
					LogTypes:         aws.StringSlice(logTypes),
				},
			},
		}

		if err := invokeLambda(awsSession, "panther-source-api", input, nil); err != nil &&
			!strings.Contains(err.Error(), "already onboarded") {

			return fmt.Errorf("error calling lambda to register account for log processing: %v", err)
		}
		logger.Infof("deploy: account %s registered for log processing", accountID)
	}

	return nil
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

func configureLogProcessingUsingAPIs(
	awsSession *session.Session, settings *config.PantherConfig, auditLogsBucket string, onboardOutputs map[string]string) error {

	// currently GuardDuty does not support this in CF
	if err := configureLogProcessingGuardDuty(awsSession, settings, auditLogsBucket, onboardOutputs); err != nil {
		return err
	}

	// configure notifications on the audit bucket, cannot be done via CF
	topicArn := onboardOutputs["LogProcessingTopicArn"]

	s3Client := s3.New(awsSession)
	input := &s3.PutBucketNotificationConfigurationInput{
		Bucket: aws.String(auditLogsBucket),
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
		return fmt.Errorf("failed to add s3 notifications to %s from %s: %v", auditLogsBucket, topicArn, err)
	}
	return nil
}

func guardDutyEnabledOutsidePanther(awsSession *session.Session, settings *config.PantherConfig) (bool, error) {
	if !settings.Setup.EnableGuardDuty {
		return false, nil
	}
	gdClient := guardduty.New(awsSession)
	input := &guardduty.ListDetectorsInput{}
	output, err := gdClient.ListDetectors(input)
	if err != nil {
		return false, fmt.Errorf("deploy: unable to check guard duty: %v", err)
	}
	if len(output.DetectorIds) != 1 {
		return false, nil // we only make 1
	}

	// we need to check that it is THIS region's stack the enabled it
	_, onboardOutput, err := describeStack(cloudformation.New(awsSession), onboardStack)
	if err != nil {
		if errStackDoesNotExist(err) {
			return true, nil // not deployed anything yet in this region BUT it is enabled, must be another deployment
		}
		return false, fmt.Errorf("deploy: cannot check stack %s: %v", onboardStack, err)
	}
	// if my stack has no reference, then it must have been enabled by another deployment
	return onboardOutput["GuardDutyDetectorId"] == "", nil
}

func configureLogProcessingGuardDuty(
	awsSession *session.Session, settings *config.PantherConfig, auditLogsBucket string, onboardOutputs map[string]string) error {

	if !settings.Setup.EnableGuardDuty {
		return nil
	}
	gdClient := guardduty.New(awsSession)
	publishInput := &guardduty.CreatePublishingDestinationInput{
		DetectorId:      aws.String(onboardOutputs["GuardDutyDetectorId"]),
		DestinationType: aws.String("S3"),
		DestinationProperties: &guardduty.DestinationProperties{
			DestinationArn: aws.String("arn:aws:s3:::" + auditLogsBucket),
			KmsKeyArn:      aws.String(onboardOutputs["GuardDutyKmsKeyArn"]),
		},
	}
	_, err := gdClient.CreatePublishingDestination(publishInput)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to configure Guard Duty detector %s to use bucket %s with kms key %s: %v",
			onboardOutputs["GuardDutyDetectorId"], auditLogsBucket,
			onboardOutputs["GuardDutyKmsKeyArn"], err)
	}
	return nil
}
