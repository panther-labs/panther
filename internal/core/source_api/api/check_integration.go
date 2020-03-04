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
		AWSAccountID:    input.AWSAccountID,
		IntegrationType: input.IntegrationType,
	}

	if *input.IntegrationType == models.IntegrationTypeAWSScan {
		_, out.AuditRoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(auditRoleFormat, *input.AWSAccountID)))
		if aws.BoolValue(input.EnableCWESetup) {
			_, out.CWERoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(cweRoleFormat, *input.AWSAccountID)))
		}
		if aws.BoolValue(input.EnableRemediation) {
			_, out.RemediationRoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(remediationRoleFormat, *input.AWSAccountID)))
		}
	}

	if *input.IntegrationType == models.IntegrationTypeAWS3 {
		var roleCreds *credentials.Credentials
		roleCreds, out.ProcessingRoleStatus = getCredentialsWithStatus(aws.String(fmt.Sprintf(logProcessingRoleFormat, *input.AWSAccountID)))
		if len(input.S3Buckets) > 0 && *out.ProcessingRoleStatus.Healthy {
			out.S3BucketsStatus = checkBuckets(roleCreds, input.S3Buckets)
		}
		if len(input.KmsKeys) > 0 && *out.ProcessingRoleStatus.Healthy {
			out.KMSKeysStatus = checkKeys(roleCreds, input.KmsKeys)
		}
	}

	return out, nil
}
func checkKeys(roleCredentials *credentials.Credentials, keys []*string) map[string]models.SourceIntegrationItemStatus {
	kmsClient := kms.New(sess, &aws.Config{Credentials: roleCredentials})

	keyStatuses := make(map[string]models.SourceIntegrationItemStatus, len(keys))
	for _, key := range keys {
		info, err := kmsClient.DescribeKey(&kms.DescribeKeyInput{KeyId: key})
		if err != nil {
			keyStatuses[*key] = models.SourceIntegrationItemStatus{
				Healthy:      aws.Bool(false),
				ErrorMessage: aws.String(err.Error()),
			}
			continue
		}

		if !*info.KeyMetadata.Enabled {
			// If the key is disabled, we should fail as well
			keyStatuses[*key] = models.SourceIntegrationItemStatus{
				Healthy:      aws.Bool(false),
				ErrorMessage: aws.String("key disabled"),
			}
			continue
		}

		keyStatuses[*key] = models.SourceIntegrationItemStatus{
			Healthy: aws.Bool(true),
		}
	}

	return keyStatuses
}

func checkBuckets(roleCredentials *credentials.Credentials, buckets []*string) map[string]models.SourceIntegrationItemStatus {
	s3Client := s3.New(sess, &aws.Config{Credentials: roleCredentials})

	bucketStatuses := make(map[string]models.SourceIntegrationItemStatus, len(buckets))
	for _, bucket := range buckets {
		_, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: bucket})
		if err != nil {
			bucketStatuses[*bucket] = models.SourceIntegrationItemStatus{
				Healthy:      aws.Bool(false),
				ErrorMessage: aws.String(err.Error()),
			}
		} else {
			bucketStatuses[*bucket] = models.SourceIntegrationItemStatus{
				Healthy: aws.Bool(true),
			}
		}
	}

	return bucketStatuses
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
			Healthy:      aws.Bool(false),
			ErrorMessage: aws.String(err.Error()),
		}
	}

	return roleCredentials, models.SourceIntegrationItemStatus{
		Healthy: aws.Bool(true),
	}
}

func evaluateIntegration(api API, integration *models.CheckIntegrationInput) (bool, error) {
	status, err := api.CheckIntegration(integration)
	if err != nil {
		return false, err
	}

	// One of these will be nil, one of these will not. We only care about the value of the not nil one.
	passing := aws.BoolValue(status.AuditRoleStatus.Healthy) || aws.BoolValue(status.ProcessingRoleStatus.Healthy)

	// For these two, we are ok if they are not enabled or if they are passing
	passing = passing && (!aws.BoolValue(integration.EnableRemediation) || aws.BoolValue(status.RemediationRoleStatus.Healthy))
	passing = passing && (!aws.BoolValue(integration.EnableCWESetup) || aws.BoolValue(status.CWERoleStatus.Healthy))

	// For these two, we are ok if none are set or all are passing
	if len(integration.S3Buckets) > 0 {
		for _, bucket := range status.S3BucketsStatus {
			passing = passing && aws.BoolValue(bucket.Healthy)
		}
	}
	if len(integration.KmsKeys) > 0 {
		for _, key := range status.KMSKeysStatus {
			passing = passing && aws.BoolValue(key.Healthy)
		}
	}

	return passing, nil
}
