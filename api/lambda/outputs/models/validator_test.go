package models

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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const outputSet = "Slack|Sns|Email|PagerDuty|Github|Jira|Opsgenie|MsTeams|Sqs"

func expectedMsg(structName string, fieldName string, tagName string) string {
	return fmt.Sprintf(
		"Key: '%s.%s' Error:Field validation for '%s' failed on the '%s' tag",
		structName, fieldName, fieldName, tagName,
	)
}

func TestAddOutputNoName(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&AddOutputInput{
		UserID:       aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName:  aws.String(""),
		OutputConfig: &OutputConfig{Slack: &SlackConfig{WebhookURL: aws.String("https://hooks.slack.com")}},
	})
	require.Error(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput", "DisplayName", "min"), err.Error())
}

func TestAddOutputNoneSpecified(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&AddOutputInput{
		UserID:       aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName:  aws.String("mychannel"),
		OutputConfig: &OutputConfig{},
	})
	require.NotNil(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput.OutputConfig", outputSet, "exactly_one_output"), err.Error())
}

func TestAddOutputAllSpecified(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&AddOutputInput{
		UserID:      aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName: aws.String("mychannel"),
		OutputConfig: &OutputConfig{
			Slack: &SlackConfig{WebhookURL: aws.String("https://hooks.slack.com")},
			Sns:   &SnsConfig{TopicArn: aws.String("arn:aws:sns:us-west-2:123456789012:MyTopic")},
		},
	})
	require.NotNil(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput.OutputConfig", outputSet, "exactly_one_output"), err.Error())
}

func TestAddOutputValid(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	assert.NoError(t, validator.Struct(&AddOutputInput{
		UserID:      aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName: aws.String("mychannel"),
		OutputConfig: &OutputConfig{
			Slack: &SlackConfig{WebhookURL: aws.String("https://hooks.slack.com")},
		},
	}))
}

func TestAddInvalidArn(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&AddOutputInput{
		UserID:      aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName: aws.String("mytopic"),
		OutputConfig: &OutputConfig{
			Sns: &SnsConfig{TopicArn: aws.String("arn:aws:sns:invalidarn:MyTopic")},
		},
	})
	require.Error(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput.OutputConfig.Sns", "TopicArn", "snsArn"), err.Error())
}

func TestAddNonSnsArn(t *testing.T) {
	validator, err := Validator()
	require.NoError(t, err)
	err = validator.Struct(&AddOutputInput{
		UserID:      aws.String("3601990c-b566-404b-b367-3c6eacd6fe60"),
		DisplayName: aws.String("mytopic"),
		OutputConfig: &OutputConfig{
			Sns: &SnsConfig{TopicArn: aws.String("arn:aws:s3:::test-s3-bucket")},
		},
	})
	require.Error(t, err)
	assert.Equal(t, expectedMsg("AddOutputInput.OutputConfig.Sns", "TopicArn", "snsArn"), err.Error())
}
