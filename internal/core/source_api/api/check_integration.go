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
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
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
	checkIntegrationInternalError = &genericapi.InternalError{Message: "Failed to validate source. Please try again later"}
)

// CheckIntegration adds a set of new integrations in a batch.
func (api *API) CheckIntegration(input *models.CheckIntegrationInput) (*models.SourceIntegrationHealth, error) {
	zap.L().Debug("beginning source configuration check")
	switch input.IntegrationType {
	case models.IntegrationTypeAWSScan:
		return api.checkAwsScanIntegration(input), nil
	case models.IntegrationTypeAWS3:
		return api.checkAwsS3Integration(input), nil
	case models.IntegrationTypeSqs:
		return api.checkSqsQueueHealth(input), nil
	default:
		return nil, checkIntegrationInternalError
	}
}

func (api *API) checkAwsScanIntegration(input *models.CheckIntegrationInput) *models.SourceIntegrationHealth {
	out := &models.SourceIntegrationHealth{
		IntegrationType: input.IntegrationType,
		// Default to true, if these need to be checked and they are not healthy they will be overwritten
		CWERoleStatus:         models.SourceIntegrationItemStatus{Healthy: true, Message: "Real time event setup is not enabled."},
		RemediationRoleStatus: models.SourceIntegrationItemStatus{Healthy: true, Message: "Automatic remediation is not enabled."},
	}
	_, out.AuditRoleStatus = api.getCredentialsWithStatus(fmt.Sprintf(auditRoleFormat,
		input.AWSAccountID, api.Config.Region))
	if aws.BoolValue(input.EnableCWESetup) {
		_, out.CWERoleStatus = api.getCredentialsWithStatus(fmt.Sprintf(cweRoleFormat,
			input.AWSAccountID, api.Config.Region))
	}
	if aws.BoolValue(input.EnableRemediation) {
		_, out.RemediationRoleStatus = api.getCredentialsWithStatus(fmt.Sprintf(remediationRoleFormat,
			input.AWSAccountID, api.Config.Region))
	}
	return out
}

func (api *API) checkAwsS3Integration(input *models.CheckIntegrationInput) *models.SourceIntegrationHealth {
	out := &models.SourceIntegrationHealth{
		IntegrationType: input.IntegrationType,
	}
	var roleCreds *credentials.Credentials
	logProcessingRole := generateLogProcessingRoleArn(input.AWSAccountID, input.IntegrationLabel)
	roleCreds, out.ProcessingRoleStatus = api.getCredentialsWithStatus(logProcessingRole)

	if !out.ProcessingRoleStatus.Healthy {
		return out // can't run the next checks without a working IAM role
	}

	bucketStatus, bucketRegion := api.checkBucket(roleCreds, input.S3Bucket)
	out.S3BucketStatus = bucketStatus
	out.KMSKeyStatus = api.checkKey(roleCreds, input.KmsKey)

	s3Client := s3.New(api.AwsSession, &aws.Config{
		Credentials: roleCreds,
		Region:      bucketRegion,
	})
	h, skipped := checkGetObject(s3Client, input)
	if !skipped {
		out.GetObjectStatus = &h
	}

	return out
}

// This function checks if the IAM identity of the s3Client has permissions to
// read objects on the bucket.
// For every s3 prefix in the input, it tries to read a random file on the bucket.
// Even if the IAM role has permissions to read objects, the check may still fail due to a bucket policy or object ACL.
// See https://github.com/panther-labs/panther/issues/2586 for details.
func checkGetObject(s3Client s3iface.S3API, input *models.CheckIntegrationInput) (h models.SourceIntegrationItemStatus, skipped bool) {
	// This check must only run for sources created in Panther >= 1.16, because it needs a new
	// permission (s3.ListBucket) in the log processing role. The CFN stack of older sources doesn't have it.
	minVersion := semver.MustParse("1.16.0-a") // 1.16.0-a < 1.16.0-dev (runs in dev env) < 1.16.0
	if input.PantherVersion().LessThan(minVersion) {
		return models.SourceIntegrationItemStatus{}, true
	}

	bucket, owner, s3Prefixes := input.S3Bucket, input.AWSAccountID, input.S3PrefixLogTypes.S3Prefixes()
	prefixes := reduceNoPrefixStrings(s3Prefixes) // no need to check prefixes that overlap
	for _, p := range prefixes {
		err := checkGetObjectPrefix(s3Client, bucket, owner, p)
		if err != nil {
			return models.SourceIntegrationItemStatus{
				Healthy:      false,
				Message:      "Failed to read S3 object",
				ErrorMessage: err.Error(),
			}, false
		}
	}

	return models.SourceIntegrationItemStatus{
		Healthy: true,
		Message: "We were able to read an object on the specified S3 bucket.",
	}, false
}

func checkGetObjectPrefix(s3Client s3iface.S3API, bucket, owner, prefix string) error {
	listOutput, err := s3Client.ListObjects(&s3.ListObjectsInput{
		Bucket:              &bucket,
		ExpectedBucketOwner: &owner,
		Prefix:              &prefix,
		MaxKeys:             aws.Int64(1),
	})
	if err != nil {
		return errors.Wrap(err, "s3.ListObjects request failed")
	}

	if len(listOutput.Contents) == 0 {
		return nil
	}

	s3Obj := listOutput.Contents[0]
	_, err = s3Client.HeadObject(&s3.HeadObjectInput{
		Bucket:              &bucket,
		ExpectedBucketOwner: &owner,
		Key:                 s3Obj.Key,
	})
	if err != nil {
		return errors.Wrapf(err, "s3.HeadObject request failed for %s", *s3Obj.Key)
	}
	return nil
}

func (api *API) checkKey(roleCredentials *credentials.Credentials, key string) models.SourceIntegrationItemStatus {
	if len(key) == 0 {
		// KMS key is optional
		return models.SourceIntegrationItemStatus{
			Healthy: true,
			Message: "No KMS Key was specified.",
		}
	}

	keyARN, err := arn.Parse(key)
	if err != nil {
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			Message:      fmt.Sprintf("The KMS ARN '%s' is invalid", key),
			ErrorMessage: err.Error(),
		}
	}

	conf := &aws.Config{
		Credentials: roleCredentials,
		Region:      &keyARN.Region, // KMS key could be in another region
	}
	kmsClient := kms.New(api.AwsSession, conf)
	info, err := kmsClient.DescribeKey(&kms.DescribeKeyInput{KeyId: &key})
	if err != nil {
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			Message:      "An error occurred while trying to describe the specified KMS key.",
			ErrorMessage: err.Error(),
		}
	}

	if !aws.BoolValue(info.KeyMetadata.Enabled) {
		// If the key is disabled, we should fail as well
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			Message:      "The specified KMS Key is disabled.",
			ErrorMessage: "",
		}
	}

	return models.SourceIntegrationItemStatus{
		Healthy: true,
		Message: "We were able to call kms:DescribeKey on the specified KMS key.",
	}
}

func (api *API) checkBucket(roleCredentials *credentials.Credentials, bucket string) (models.SourceIntegrationItemStatus, *string) {
	s3Client := s3.New(api.AwsSession, &aws.Config{Credentials: roleCredentials})

	out, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: &bucket})
	if err != nil {
		return models.SourceIntegrationItemStatus{
			Healthy:      false,
			Message:      "An error occurred while trying to get the region of the specified S3 bucket.",
			ErrorMessage: err.Error(),
		}, nil
	}

	region := out.LocationConstraint
	if region == nil {
		region = aws.String(endpoints.UsEast1RegionID)
	}
	return models.SourceIntegrationItemStatus{
		Healthy: true,
		Message: "We were able to call s3:GetBucketLocation on the specified S3 bucket.",
	}, region
}

func (api *API) getCredentialsWithStatus(roleARN string) (*credentials.Credentials, models.SourceIntegrationItemStatus) {
	zap.L().Debug("checking role", zap.String("roleArn", roleARN))
	// Setup new credentials with the role
	roleCredentials := stscreds.NewCredentials(
		api.AwsSession,
		roleARN,
	)

	// Use the role to make sure it's good
	stsClient := sts.New(api.AwsSession, aws.NewConfig().WithCredentials(roleCredentials))
	_, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return roleCredentials, models.SourceIntegrationItemStatus{
			Healthy:      false,
			Message:      fmt.Sprintf("We were unable to assume %s", roleARN),
			ErrorMessage: err.Error(),
		}
	}

	return roleCredentials, models.SourceIntegrationItemStatus{
		Healthy: true,
		Message: fmt.Sprintf("We were able to successfully assume %s", roleARN),
	}
}

func (api *API) evaluateIntegration(integration *models.CheckIntegrationInput) (string, bool, error) {
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
			return status.AuditRoleStatus.Message, false, nil
		}

		if aws.BoolValue(integration.EnableRemediation) && !status.RemediationRoleStatus.Healthy {
			return status.RemediationRoleStatus.Message, false, nil
		}

		if aws.BoolValue(integration.EnableCWESetup) && !status.CWERoleStatus.Healthy {
			return status.CWERoleStatus.Message, false, nil
		}
		return "", true, nil
	case models.IntegrationTypeAWS3:
		if !status.ProcessingRoleStatus.Healthy {
			return status.ProcessingRoleStatus.Message, false, nil
		}

		if !status.S3BucketStatus.Healthy {
			return status.S3BucketStatus.Message, false, nil
		}

		if !status.KMSKeyStatus.Healthy {
			return status.KMSKeyStatus.Message, false, nil
		}

		if !status.GetObjectStatus.Healthy {
			return status.GetObjectStatus.Message, false, nil
		}

		return "", true, nil
	case models.IntegrationTypeSqs:
		if !status.SqsStatus.Healthy {
			return status.SqsStatus.Message, false, nil
		}
		return status.SqsStatus.Message, true, nil

	default:
		return "", false, errors.New("invalid integration type")
	}
}

// Check the health of the SQS source
func (api *API) checkSqsQueueHealth(input *models.CheckIntegrationInput) *models.SourceIntegrationHealth {
	health := &models.SourceIntegrationHealth{
		IntegrationType: input.IntegrationType,
	}

	// If the Queue URL is not populated, it means that the SQS queue has not yet been created
	// In such a case, the health check can just return true, since there is no check to be performed.
	// This can happen during the initial health-check performed by the frontend, since the health check
	// is performed before the SQS queue is created.
	if len(input.SqsConfig.QueueURL) == 0 {
		health.SqsStatus.Healthy = true
		health.SqsStatus.Message = "Queue does not exist yet (first time setup)."
		return health
	}

	getAttributesInput := &sqs.GetQueueAttributesInput{
		QueueUrl: &input.SqsConfig.QueueURL,
	}
	_, err := api.SqsClient.GetQueueAttributes(getAttributesInput)
	if err != nil {
		health.SqsStatus.Healthy = false
		health.SqsStatus.Message = "An error occurred while trying to get the attributes of the specified SQS queue."
		health.SqsStatus.ErrorMessage = err.Error()
		return health
	}

	health.SqsStatus.Healthy = true
	health.SqsStatus.Message = "We were able to call sqs:GetQueueAttributes on the specified SQS queue."
	return health
}
