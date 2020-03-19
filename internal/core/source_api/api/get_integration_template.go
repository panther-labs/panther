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
	"bytes"
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
	TemplateBucket           = "panther-public-cloudformation-templates"
	CloudSecurityTemplateKey = "panther-compliance-iam/v1.0.2/template.yml"
	LogProcessingTemplateKey = "panther-log-processing-iam/latest/template.yml"
	cacheTimout              = time.Minute * 30
)

var (
	templateCache = make(map[string]templateCacheItem, 2)

	// Formatting variables used for re-writing the default templates
	accountIDFind    = []byte("Value: '' # MasterAccountId")
	accountIDReplace = "Value: %s # MasterAccountId"

	// Formatting variables for Cloud Security
	cweFind            = []byte("Value: '' # DeployCloudWatchEventSetup")
	cweReplace         = "Value: %t # DeployCloudWatchEventSetup"
	remediationFind    = []byte("Value: '' # DeployRemediation")
	remediationReplace = "Value: %t # DeployRemediation"

	// Formatting variables for Log Analysis
	s3BucketFind    = []byte("Default: '' # S3Buckets")
	s3BucketReplace = "Default: %s # S3Buckets"
	kmsKeyFind      = []byte("Default: '' # EncryptionKeys")
	kmsKeyReplace   = "Default: %s # EncryptionKeys"
)

type templateCacheItem struct {
	Timestamp time.Time
	Body      []byte
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
	formattedTemplate := bytes.Replace(template, accountIDFind,
		[]byte(fmt.Sprintf(accountIDReplace, *input.AWSAccountID)), 1)

	// Cloud Security replacements
	formattedTemplate = bytes.Replace(formattedTemplate, cweFind,
		[]byte(fmt.Sprintf(cweReplace, *input.CWEEnabled)), 1)
	formattedTemplate = bytes.Replace(formattedTemplate, remediationFind,
		[]byte(fmt.Sprintf(remediationReplace, *input.RemediationEnabled)), 1)

	// Log Analysis replacements
	formattedTemplate = bytes.Replace(formattedTemplate, s3BucketFind,
		[]byte(fmt.Sprintf(s3BucketReplace, strings.Join(sliceStringValue(input.S3Buckets), ","))), 1)
	formattedTemplate = bytes.Replace(formattedTemplate, kmsKeyFind,
		[]byte(fmt.Sprintf(kmsKeyReplace, strings.Join(sliceStringValue(input.KmsKeys), ","))), 1)

	return &models.SourceIntegrationTemplate{
		Body: aws.String(string(formattedTemplate)),
	}, nil
}

func sliceStringValue(stringPointers []*string) []string {
	out := make([]string, 0, len(stringPointers))
	for index, ptr := range stringPointers {
		out[index] = aws.StringValue(ptr)
	}
	return out
}

func getTemplate(integrationType *string) ([]byte, error) {
	// First check the cache
	if item, ok := templateCache[*integrationType]; ok && time.Since(item.Timestamp) < cacheTimout {
		zap.L().Debug("using cached template")
		return item.Body, nil
	}

	// Get the template from Panther's public S3 bucket
	s3Svc := s3.New(sess, &aws.Config{
		Region: aws.String("us-west-2"),
	})
	templateRequest := &s3.GetObjectInput{
		Bucket: aws.String(TemplateBucket),
	}
	if *integrationType == models.IntegrationTypeAWSScan {
		templateRequest.Key = aws.String(CloudSecurityTemplateKey)
	} else {
		templateRequest.Key = aws.String(LogProcessingTemplateKey)
	}
	template, err := s3Svc.GetObject(templateRequest)
	if err != nil {
		return nil, err
	}

	// Load the template into memory. They're only ~8Kb in size.
	templateBody, err := ioutil.ReadAll(template.Body)
	if err != nil {
		return nil, err
	}

	// Update the cache
	templateCache[*integrationType] = templateCacheItem{
		Timestamp: time.Now(),
		Body:      templateBody,
	}

	// Return the template
	return templateBody, nil
}
