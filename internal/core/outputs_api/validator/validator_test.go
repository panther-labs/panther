package validator

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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

func expectedMsg(structName string, fieldName string, tagName string) string {
	return fmt.Sprintf(
		"Key: '%s.%s' Error:Field validation for '%s' failed on the '%s' tag",
		structName, fieldName, fieldName, tagName,
	)
}

func TestAddOutputNoName(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&models.AddOutputInput{
		UserID:       aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName:  aws.String(""),
		AlertTypes:   []string{deliverymodel.RuleType},
		OutputConfig: &models.OutputConfig{Slack: &models.SlackConfig{WebhookURL: "https://hooks.slack.com"}},
	})
	require.Error(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput", "DisplayName", "min"), err.Error())
}

func TestAddOutputValid(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	assert.NoError(t, validator.Struct(&models.AddOutputInput{
		UserID:      aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName: aws.String("mychannel"),
		AlertTypes:  []string{deliverymodel.RuleType},
		OutputConfig: &models.OutputConfig{
			Slack: &models.SlackConfig{WebhookURL: "https://hooks.slack.com"},
		},
	}))
}

func TestAddInvalidArn(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&models.AddOutputInput{
		UserID:      aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName: aws.String("mytopic"),
		AlertTypes:  []string{deliverymodel.RuleType},
		OutputConfig: &models.OutputConfig{
			Sns: &models.SnsConfig{TopicArn: "arn:aws:sns:invalidarn:MyTopic"},
		},
	})
	require.Error(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput.OutputConfig.Sns", "TopicArn", "snsArn"), err.Error())
}

func TestAddNonSnsArn(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&models.AddOutputInput{
		UserID:      aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName: aws.String("mytopic"),
		AlertTypes:  []string{deliverymodel.RuleType},
		OutputConfig: &models.OutputConfig{
			Sns: &models.SnsConfig{TopicArn: "arn:aws:s3:::test-s3-bucket"},
		},
	})
	require.Error(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput.OutputConfig.Sns", "TopicArn", "snsArn"), err.Error())
}
