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
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/snapshot/models"
)

const (
	auditRoleFormat         = "arn:aws:iam::%s:role/PantherAuditRole"
	logProcessingRoleFormat = "arn:aws:iam::%s:role/PantherLogProcessingRole"
	cweRoleFormat           = "arn:aws:iam::%s:role/PantherCloudFormationStackSetExecutionRole"
	remediationRoleFormat   = "arn:aws:iam::%s:role/PantherRemediationRole"
)

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
	}

	return out, nil
}

func checkBuckets(roleCredentials *credentials.Credentials, buckets []*string) map[string]*models.SourceIntegrationItemStatus {
	s3Client := s3.New(sess, &aws.Config{Credentials: roleCredentials})

	bucketStatuses := make(map[string]*models.SourceIntegrationItemStatus, len(buckets))
	for _, bucket := range buckets {
		_, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: bucket})
		if err != nil {
			bucketStatuses[*bucket] = &models.SourceIntegrationItemStatus{
				Healthy:      aws.Bool(false),
				ErrorMessage: aws.String(err.Error()),
			}
		} else {
			bucketStatuses[*bucket] = &models.SourceIntegrationItemStatus{
				Healthy: aws.Bool(true),
			}
		}
	}

	return bucketStatuses
}

func getCredentialsWithStatus(
	roleARN *string,
) (*credentials.Credentials, *models.SourceIntegrationItemStatus) {

	zap.L().Info("checking role", zap.String("roleArn", *roleARN))
	// Setup new credentials with the role
	roleCredentials := stscreds.NewCredentials(
		sess,
		*roleARN,
	)

	// Use the role to make sure it's good
	stsClient := sts.New(sess, &aws.Config{Credentials: roleCredentials})
	_, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return roleCredentials, &models.SourceIntegrationItemStatus{
			Healthy:      aws.Bool(false),
			ErrorMessage: aws.String(err.Error()),
		}
	}

	return roleCredentials, &models.SourceIntegrationItemStatus{
		Healthy: aws.Bool(true),
	}
}
