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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

const (
	// Formatting variables used for re-writing the default templates
	accountIDFind    = "Value: '' # MasterAccountId"
	accountIDReplace = "Value: '%s' # MasterAccountId"

	// Formatting variables for Cloud Security
	regionFind         = "Value: '' # MasterAccountRegion"
	regionReplace      = "Value: '%s' # MasterAccountRegion"
	cweFind            = "Value: '' # DeployCloudWatchEventSetup"
	cweReplace         = "Value: '%t' # DeployCloudWatchEventSetup"
	remediationFind    = "Value: '' # DeployRemediation"
	remediationReplace = "Value: '%t' # DeployRemediation"

	// Formatting variables for Log Analysis
	roleSuffixIDFind  = "Value: '' # RoleSuffix"
	roleSuffixReplace = "Value: '%s' # RoleSuffix"
	s3BucketFind      = "Value: '' # S3Bucket"
	s3BucketReplace   = "Value: '%s' # S3Bucket"
	s3PrefixFind      = "Value: '' # S3Prefix"
	s3PrefixReplace   = "Value: '%s' # S3Prefix"
	kmsKeyFind        = "Value: '' # KmsKey"
	kmsKeyReplace     = "Value: '%s' # KmsKey"
)

// GetIntegrationTemplate generates a new satellite account CloudFormation template based on the given parameters.
func (API) GetIntegrationTemplate(input *models.GetIntegrationTemplateInput) (*models.SourceIntegrationTemplate, error) {
	zap.L().Debug("constructing source template")

	// Format the template with the user's input
	formattedTemplate := strings.Replace(getTemplate(input.IntegrationType), accountIDFind,
		fmt.Sprintf(accountIDReplace, *input.AWSAccountID), 1)

	// Cloud Security replacements
	if *input.IntegrationType == models.IntegrationTypeAWSScan {
		formattedTemplate = strings.Replace(formattedTemplate, regionFind,
			fmt.Sprintf(regionReplace, *sess.Config.Region), 1)
		formattedTemplate = strings.Replace(formattedTemplate, cweFind,
			fmt.Sprintf(cweReplace, aws.BoolValue(input.CWEEnabled)), 1)
		formattedTemplate = strings.Replace(formattedTemplate, remediationFind,
			fmt.Sprintf(remediationReplace, aws.BoolValue(input.RemediationEnabled)), 1)
	} else {
		// Log Analysis replacements
		formattedTemplate = strings.Replace(formattedTemplate, roleSuffixIDFind,
			fmt.Sprintf(roleSuffixReplace, generateRoleSuffix(*input.IntegrationLabel)), 1)

		formattedTemplate = strings.Replace(formattedTemplate, s3BucketFind,
			fmt.Sprintf(s3BucketReplace, *input.S3Bucket), 1)

		if input.S3Prefix != nil {
			formattedTemplate = strings.Replace(formattedTemplate, s3PrefixFind,
				fmt.Sprintf(s3PrefixReplace, *input.S3Prefix), 1)
		} else {
			// If no S3Prefix is specified, add as default '*'
			formattedTemplate = strings.Replace(formattedTemplate, s3PrefixFind,
				fmt.Sprintf(s3PrefixReplace, "*"), 1)
		}

		if input.KmsKey != nil {
			formattedTemplate = strings.Replace(formattedTemplate, kmsKeyFind,
				fmt.Sprintf(kmsKeyReplace, *input.KmsKey), 1)
		}
	}

	return &models.SourceIntegrationTemplate{
		Body: aws.String(formattedTemplate),
	}, nil
}

func getTemplate(integrationType *string) string {
	switch *integrationType {
	case models.IntegrationTypeAWSScan:
		return cloudsecTemplate
	case models.IntegrationTypeAWS3:
		return logAnalysisTemplate
	default:
		panic("unknown integration type: " + *integrationType)
	}
}

// Generates the ARN of the log processing role
func generateLogProcessingRoleArn(awsAccountID string, label string) string {
	return fmt.Sprintf(logProcessingRoleFormat, awsAccountID, generateRoleSuffix(label))
}

func generateRoleSuffix(label string) string {
	sanitized := strings.ReplaceAll(label, " ", "-")
	return strings.ToLower(sanitized)
}
