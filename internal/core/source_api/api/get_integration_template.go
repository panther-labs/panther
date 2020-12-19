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
	"io/ioutil"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

const (
	TemplateBucket = "panther-public-cloudformation-templates"

	LogAnalysisStackNameTemplate = "panther-log-analysis-setup-%s"
	CloudSecStackName            = "panther-cloudsec-setup"

	cacheTimeout = time.Minute * 30

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
	kmsKeyFind        = "Value: '' # KmsKey"
	kmsKeyReplace     = "Value: '%s' # KmsKey"
)

var (
	templateCache = make(map[string]templateCacheItem, 2)
)

type templateCacheItem struct {
	Timestamp time.Time
	Body      string
}

// GetIntegrationTemplate generates a new satellite account CloudFormation template based on the given parameters.
func (API) GetIntegrationTemplate(input *models.GetIntegrationTemplateInput) (*models.SourceIntegrationTemplate, error) {
	zap.L().Debug("constructing source template")

	// Get the template
	template, err := getTemplate(input.IntegrationType)
	if err != nil {
		return nil, err
	}

	// Format the template with the user's input
	formattedTemplate := strings.Replace(template, accountIDFind,
		fmt.Sprintf(accountIDReplace, input.AWSAccountID), 1)

	// Cloud Security replacements
	if input.IntegrationType == models.IntegrationTypeAWSScan {
		formattedTemplate = strings.Replace(formattedTemplate, regionFind,
			fmt.Sprintf(regionReplace, *awsSession.Config.Region), 1)
		formattedTemplate = strings.Replace(formattedTemplate, cweFind,
			fmt.Sprintf(cweReplace, aws.BoolValue(input.CWEEnabled)), 1)
		formattedTemplate = strings.Replace(formattedTemplate, remediationFind,
			fmt.Sprintf(remediationReplace, aws.BoolValue(input.RemediationEnabled)), 1)
	} else {
		// Log Analysis replacements
		formattedTemplate = strings.Replace(formattedTemplate, roleSuffixIDFind,
			fmt.Sprintf(roleSuffixReplace, normalizedLabel(input.IntegrationLabel)), 1)

		formattedTemplate = strings.Replace(formattedTemplate, s3BucketFind,
			fmt.Sprintf(s3BucketReplace, input.S3Bucket), 1)

		if len(input.KmsKey) > 0 {
			formattedTemplate = strings.Replace(formattedTemplate, kmsKeyFind,
				fmt.Sprintf(kmsKeyReplace, input.KmsKey), 1)
		}
	}

	return &models.SourceIntegrationTemplate{
		Body:      formattedTemplate,
		StackName: getStackName(input.IntegrationType, input.IntegrationLabel),
	}, nil
}

func getTemplate(integrationType string) (string, error) {
	// First check the cache
	if item, ok := templateCache[integrationType]; ok && time.Since(item.Timestamp) < cacheTimeout {
		zap.L().Debug("using cached s3Object")
		return item.Body, nil
	}

	templateRequest := &s3.GetObjectInput{
		Bucket: aws.String(TemplateBucket),
	}

	if integrationType == models.IntegrationTypeAWSScan {
		templateRequest.Key = aws.String("panther-cloudsec-iam/v" + env.Version + "/template.yml")
	} else {
		templateRequest.Key = aws.String("panther-log-analysis-iam/v" + env.Version + "/template.yml")
	}
	zap.L().Debug("requesting template", zap.String("key", *templateRequest.Key), zap.String("bucket", *templateRequest.Bucket))
	s3Object, err := templateS3Client.GetObject(templateRequest)
	if err != nil {
		return "", err
	}

	// Load the s3Object into memory. They're only ~8Kb in size.
	templateBody, err := ioutil.ReadAll(s3Object.Body)
	if err != nil {
		return "", err
	}

	templateBodyString := string(templateBody)
	// Update the cache
	templateCache[integrationType] = templateCacheItem{
		Timestamp: time.Now(),
		Body:      templateBodyString,
	}

	// Return the s3Object
	return templateBodyString, nil
}

func getStackName(integrationType string, label string) string {
	if integrationType == models.IntegrationTypeAWSScan {
		return CloudSecStackName
	}
	return fmt.Sprintf(LogAnalysisStackNameTemplate, normalizedLabel(label))
}

// Generates the ARN of the log processing role
func generateLogProcessingRoleArn(awsAccountID string, label string) string {
	return fmt.Sprintf(logProcessingRoleFormat, awsAccountID, normalizedLabel(label))
}

func normalizedLabel(label string) string {
	sanitized := strings.ReplaceAll(label, " ", "-")
	return strings.ToLower(sanitized)
}
