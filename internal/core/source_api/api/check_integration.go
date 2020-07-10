package api

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	auditRoleFormat         = "arn:aws:iam::%s:role/PantherAuditRole-%s"
	logProcessingRoleFormat = "arn:aws:iam::%s:role/PantherLogProcessingRole-%s"
	cweRoleFormat           = "arn:aws:iam::%s:role/PantherCloudFormationStackSetExecutionRole-%s"
	remediationRoleFormat   = "arn:aws:iam::%s:role/PantherRemediationRole-%s"
)

var (
	evaluateIntegrationFunc       = evaluateIntegration
	checkIntegrationInternalError = &genericapi.InternalError{Message: "Failed to validate source. Please try again later"}
)

// CheckIntegration adds a set of new integrations in a batch.
func (API) CheckIntegration(input *models.CheckIntegrationInput) (*models.SourceIntegrationHealth, error) {
	zap.L().Debug("beginning source configuration check")
	switch input.IntegrationType {
	case models.IntegrationTypeAWSScan:
		return checkAwsScanIntegration(input), nil
	case models.IntegrationTypeAWS3:
		return checkAwsS3Integration(input), nil
	default:
		return nil, checkIntegrationInternalError
	}
}

func checkAwsScanIntegration(input *models.CheckIntegrationInput) *models.SourceIntegrationHealth {
	out := &models.SourceIntegrationHealth{
		IntegrationType: input.IntegrationType,
	}
	_, out.AuditRoleStatus = getCredentialsWithStatus(fmt.Sprintf(auditRoleFormat,
		input.AWSAccountID, *awsSession.Config.Region))
	if aws.BoolValue(input.EnableCWESetup) {
		_, out.CWERoleStatus = getCredentialsWithStatus(fmt.Sprintf(cweRoleFormat,
			input.AWSAccountID, *awsSession.Config.Region))
	}
	if aws.BoolValue(input.EnableRemediation) {
		_, out.RemediationRoleStatus = getCredentialsWithStatus(fmt.Sprintf(remediationRoleFormat,
			input.AWSAccountID, *awsSession.Config.Region))
	}
	return out
}

func checkAwsS3Integration(input *models.CheckIntegrationInput) *models.SourceIntegrationHealth {
	out := &models.SourceIntegrationHealth{
		IntegrationType: input.IntegrationType,
	}
	var roleCreds *credentials.Credentials
	logProcessingRole := generateLogProcessingRoleArn(input.AWSAccountID, input.IntegrationLabel)
	roleCreds, out.ProcessingRoleStatus = getCredentialsWithStatus(logProcessingRole)
	if out.ProcessingRoleStatus.Healthy {
		out.S3BucketStatus = checkBucket(roleCreds, input.S3Bucket)
		out.KMSKeyStatus = checkKey(roleCreds, input.KmsKey)
	}
	return out
}

func checkKey(roleCredentials *credentials.Credentials, key string) models.SourceIntegrationItemStatus {
	if len(key) == 0 {
		// KMS key is optional
		return models.SourceIntegrationItemStatus{
			Healthy: true,
		}
	}
	kmsClient := kms.New(awsSession, &aws.Config{Credentials: roleCredentials})

	info, err := kmsClient.DescribeKey(&kms.DescribeKeyInput{KeyId: &key})
	if err != nil {
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			ErrorMessage: err.Error(),
		}
	}

	if !aws.BoolValue(info.KeyMetadata.Enabled) {
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

func checkBucket(roleCredentials *credentials.Credentials, bucket string) models.SourceIntegrationItemStatus {
	s3Client := s3.New(awsSession, &aws.Config{Credentials: roleCredentials})

	_, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: &bucket})
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

func getCredentialsWithStatus(roleARN string) (*credentials.Credentials, models.SourceIntegrationItemStatus) {
	zap.L().Debug("checking role", zap.String("roleArn", roleARN))
	// Setup new credentials with the role
	roleCredentials := stscreds.NewCredentials(
		awsSession,
		roleARN,
	)

	// Use the role to make sure it's good
	stsClient := sts.New(awsSession, aws.NewConfig().WithCredentials(roleCredentials))
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

func evaluateIntegration(api API, integration *models.CheckIntegrationInput) (string, bool, error) {
	status, err := api.CheckIntegration(integration)
	if err != nil {
		zap.L().Error("integration failed configuration check",
			zap.Error(err),
			zap.Any("integration", integration),
			zap.Any("status", status))
		return "", false, err
	}

	switch integration.IntegrationType {
	case models.IntegrationTypeAWSScan:
		if !status.AuditRoleStatus.Healthy {
			return "cannot assume audit role", false, nil
		}

		if aws.BoolValue(integration.EnableRemediation) && !status.RemediationRoleStatus.Healthy {
			return "cannot assume remediation role", false, nil
		}

		if aws.BoolValue(integration.EnableCWESetup) && !status.CWERoleStatus.Healthy {
			return "cannot assume cwe role", false, nil
		}
		return "", true, nil
	case models.IntegrationTypeAWS3:
		if !status.ProcessingRoleStatus.Healthy {
			return "cannot assume log processing role", false, nil
		}

		if !status.S3BucketStatus.Healthy {
			return "log processing role cannot access s3 bucket", false, nil
		}

		if !status.KMSKeyStatus.Healthy {
			return "log processing role cannot access kms key", false, nil
		}
		return "", true, nil
	default:
		return "", false, errors.New("invalid integration type")
	}
}
