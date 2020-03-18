package api

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

const (
	auditRoleFormat         = "arn:aws:iam::%s:role/PantherAuditRole"
	logProcessingRoleFormat = "arn:aws:iam::%s:role/PantherLogProcessingRole"
	cweRoleFormat           = "arn:aws:iam::%s:role/PantherCloudFormationStackSetExecutionRole"
	remediationRoleFormat   = "arn:aws:iam::%s:role/PantherRemediationRole"
)

var evaluateIntegrationFunc = evaluateIntegration

// CheckIntegration adds a set of new integrations in a batch.
func (API) CheckIntegration(input *models.CheckIntegrationInput) (*models.SourceIntegrationHealth, error) {
	zap.L().Debug("beginning source health check")
	out := &models.SourceIntegrationHealth{
		AWSAccountID:    aws.StringValue(input.AWSAccountID),
		IntegrationType: aws.StringValue(input.IntegrationType),
	}

	if *input.IntegrationType == models.IntegrationTypeAWSScan {
		_, out.AuditRoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(auditRoleFormat, *input.AWSAccountID)))
		if aws.BoolValue(input.EnableCWESetup) {
			_, out.CWERoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(cweRoleFormat, *input.AWSAccountID)))
		}
		if aws.BoolValue(input.EnableRemediation) {
			_, out.RemediationRoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(remediationRoleFormat, *input.AWSAccountID)))
		}
	} else {
		var roleCreds *credentials.Credentials
		roleCreds, out.ProcessingRoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(logProcessingRoleFormat, *input.AWSAccountID)))
		if out.ProcessingRoleStatus.Healthy {
			out.S3BucketStatus = checkBucket(roleCreds, input.S3Bucket)
			out.KMSKeyStatus = checkKey(roleCreds, input.KmsKey)
		}
	}

	return out, nil
}
func checkKey(roleCredentials *credentials.Credentials, key *string) models.SourceIntegrationItemStatus {
	if key == nil {
		// KMS key is optional
		return models.SourceIntegrationItemStatus{
			Healthy: true,
		}
	}
	kmsClient := kms.New(sess, &aws.Config{Credentials: roleCredentials})

	info, err := kmsClient.DescribeKey(&kms.DescribeKeyInput{KeyId: key})
	if err != nil {
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			ErrorMessage: err.Error(),
		}
	}

	if !*info.KeyMetadata.Enabled {
		// If the key is disabled, we should fail as well
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			ErrorMessage: "key disabled",
		}
	}

	return models.SourceIntegrationItemStatus{
		Healthy: true,
	}
}

func checkBucket(roleCredentials *credentials.Credentials, bucket *string) models.SourceIntegrationItemStatus {
	s3Client := s3.New(sess, &aws.Config{Credentials: roleCredentials})

	_, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: bucket})
	if err != nil {
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			ErrorMessage: err.Error(),
		}
	}

	return models.SourceIntegrationItemStatus{
		Healthy: true,
	}
}

func getCredentialsWithStatus(
	roleARN *string,
) (*credentials.Credentials, models.SourceIntegrationItemStatus) {

	zap.L().Debug("checking role", zap.String("roleArn", *roleARN))
	// Setup new credentials with the role
	roleCredentials := stscreds.NewCredentials(
		sess,
		*roleARN,
	)

	// Use the role to make sure it's good
	stsClient := sts.New(sess, &aws.Config{Credentials: roleCredentials})
	_, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return roleCredentials, models.SourceIntegrationItemStatus{
			Healthy:      false,
			ErrorMessage: err.Error(),
		}
	}

	return roleCredentials, models.SourceIntegrationItemStatus{
		Healthy: true,
	}
}

func evaluateIntegration(api API, integration *models.CheckIntegrationInput) (bool, error) {
	status, err := api.CheckIntegration(integration)
	if err != nil {
		return false, err
	}

	if *integration.IntegrationType == models.IntegrationTypeAWSScan {
		passing := status.AuditRoleStatus.Healthy
		// For these two, we are ok if they are not enabled or if they are passing
		passing = passing && (!aws.BoolValue(integration.EnableRemediation) || status.RemediationRoleStatus.Healthy)
		passing = passing && (!aws.BoolValue(integration.EnableCWESetup) || status.CWERoleStatus.Healthy)
		return passing, nil
	}
	// One of these will be nil, one of these will not. We only care about the value of the not nil one.
	return status.ProcessingRoleStatus.Healthy && status.S3BucketStatus.Healthy && status.KMSKeyStatus.Healthy, nil
}
