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
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
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

	var err error
	if *input.IntegrationType == models.IntegrationTypeAWSScan {
		out.AuditRoleGood, err = checkAuditRole(input.AWSAccountID)
		if err != nil {
			return nil, err
		}
	}

	if *input.IntegrationType == models.IntegrationTypeAWS3 {
		out.ProcessingRoleGood, err = checkLogProcessingRole(input.AWSAccountID)
		if err != nil {
			return nil, err
		}
	}

	if aws.BoolValue(input.EnableCWESetup) {
		out.CWERoleGood, err = checkCWERole(input.AWSAccountID)
		if err != nil {
			return nil, err
		}
	}

	if aws.BoolValue(input.EnableRemediation) {
		out.RemediationRoleGood, err = checkRemediationRole(input.AWSAccountID)
		if err != nil {
			return nil, err
		}
	}

	if len(input.S3Buckets) > 0 {
		out.S3BucketsGood, err = checkBuckets(input.AWSAccountID, input.S3Buckets)
		if err != nil {
			return nil, err
		}
	}

	if len(input.KmsKeys) > 0 {
		out.KmsKeysGood, err = checkKeys(input.AWSAccountID, input.KmsKeys)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

func checkAuditRole(accountID *string) (*bool, error) {
	return checkRole(aws.String(fmt.Sprintf(auditRoleFormat, *accountID)))
}
func checkCWERole(accountID *string) (*bool, error) {
	return checkRole(aws.String(fmt.Sprintf(cweRoleFormat, *accountID)))
}
func checkRemediationRole(accountID *string) (*bool, error) {
	return checkRole(aws.String(fmt.Sprintf(remediationRoleFormat, *accountID)))
}
func checkLogProcessingRole(accountID *string) (*bool, error) {
	return checkRole(aws.String(fmt.Sprintf(logProcessingRoleFormat, *accountID)))
}
func checkBuckets(_ *string, _ []*string) (map[string]*bool, error) {
	return nil, nil
}
func checkKeys(_ *string, _ []*string) (map[string]*bool, error) {
	return nil, nil
}

func checkRole(
	roleARN *string,
) (*bool, error) {

	zap.L().Info("checking role", zap.String("roleArn", *roleARN))
	creds := stscreds.NewCredentials(
		sess,
		*roleARN,
	)
	stsClient := sts.New(sess, &aws.Config{Credentials: creds})

	_, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})

	if err != nil {
		return aws.Bool(false), nil
	}

	return aws.Bool(true), nil
}
