package main

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
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	outputsAPI        = "panther-outputs-api"
	defaultsTableName = "panther-default-outputs"
	tableName         = "panther-outputs"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	lambdaClient    = lambda.New(awsSession)

	slack = &models.SlackConfig{
		WebhookURL: aws.String("https://hooks.slack.com/services/AAAAAAAAA/BBBBBBBBB/" +
			"abcdefghijklmnopqrstuvwx"),
	}
	sns       = &models.SnsConfig{TopicArn: aws.String("arn:aws:sns:us-west-2:123456789012:MyTopic")}
	pagerDuty = &models.PagerDutyConfig{IntegrationKey: aws.String("7a08481fbc0746c9a8a487f90d737e05")}
	snsType   = aws.String("sns")
	userID    = aws.String("43808de4-fbae-4f90-a9b4-1e4982d65287")

	// Remember the generated output IDs
	slackOutputID     *string
	snsOutputID       *string
	pagerDutyOutputID *string
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	os.Exit(m.Run())
}

// TestIntegrationAPI is the single integration test - invokes the live Lambda function.
func TestIntegrationAPI(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	require.NoError(t, testutils.ClearDynamoTable(awsSession, tableName))
	require.NoError(t, testutils.ClearDynamoTable(awsSession, defaultsTableName))

	// Add one of each output type in parallel.
	t.Run("Add", func(t *testing.T) {
		t.Run("AddInvalid", addInvalid)
		t.Run("AddSlack", addSlack)
		t.Run("AddSns", addSns)
		t.Run("AddPagerDuty", addPagerDuty)
	})
	if t.Failed() {
		return
	}

	// Duplicate names shouldn't be allowed.
	t.Run("AddSnsDuplicate", addSnsDuplicate)
	if t.Failed() {
		return
	}

	t.Run("SetDefaultOutputs", setDefaultOutput)
	if t.Failed() {
		return
	}

	// Get outputs in parallel
	t.Run("Get", func(t *testing.T) {
		t.Run("GetOrganizationOutputs", getOrganizationOutputs)
		t.Run("GetOutput", getOutput)
		t.Run("GetDefaults", getDefaults)
	})
	if t.Failed() {
		return
	}

	t.Run("SetDefaultOutputs", setDefaultOutput)
	if t.Failed() {
		return
	}

	t.Run("DeleteOutputInUse", deleteOutputInUse)
	if t.Failed() {
		return
	}

	t.Run("ForceDeleteOutputInUse", forceDeleteOutputInUse)
	if t.Failed() {
		return
	}

	// Update each output in parallel.
	t.Run("Update", func(t *testing.T) {
		t.Run("UpdateInvalid", updateInvalid)
		t.Run("UpdateSlack", updateSlack)
		t.Run("UpdateSns", updateSns)
	})
	if t.Failed() {
		return
	}

	// Delete each output in parallel.
	t.Run("Delete", func(t *testing.T) {
		t.Run("DeleteInvalid", deleteInvalid)
		t.Run("DeleteSns", deleteSns)
	})
	if t.Failed() {
		return
	}

	// All these operations should fail
	t.Run("EmptyOperations", func(t *testing.T) {
		t.Run("DeleteSnsEmpty", deleteSnsEmpty)
		t.Run("UpdateSnsEmpty", updateSnsEmpty)
		t.Run("GetOutputEmpty", getSnsEmpty)
		t.Run("SetDefaultOutputDoesntExist", setDefaultOutputDoesntExist)
	})
	if t.Failed() {
		return
	}
}

// ********** Subtests **********

func addInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		AddOutput: &models.AddOutputInput{
			UserID:       userID,
			OutputConfig: &models.OutputConfig{Sns: sns},
		},
	}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("AddOutput failed: invalid input: " +
			"Key: 'LambdaInput.AddOutput.DisplayName' " +
			"Error:Field validation for 'DisplayName' failed on the 'required' tag"),
		ErrorType:    aws.String("InvalidInputError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expected, err)
}

func addSlack(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		AddOutput: &models.AddOutputInput{
			UserID:             userID,
			DisplayName:        aws.String("alert-channel"),
			OutputConfig:       &models.OutputConfig{Slack: slack},
			DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
		},
	}
	var output models.AddOutputOutput
	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.NotNil(t, output.OutputID)
	assert.Equal(t, aws.String("alert-channel"), output.DisplayName)
	assert.Equal(t, aws.String("slack"), output.OutputType)

	defaults, err := getDefaultOutputsInternal()
	require.NoError(t, err)
	expectedDefaultOutputs := &models.DefaultOutputs{
		Severity:  aws.String("HIGH"),
		OutputIDs: []*string{output.OutputID},
	}
	assert.Equal(t, []*models.DefaultOutputs{expectedDefaultOutputs}, defaults.Defaults)

	slackOutputID = output.OutputID
}

func addSns(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		AddOutput: &models.AddOutputInput{
			UserID:       userID,
			DisplayName:  aws.String("alert-topic"),
			OutputConfig: &models.OutputConfig{Sns: sns},
		},
	}
	var output models.AddOutputOutput

	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.NotNil(t, output.OutputID)
	assert.Equal(t, input.AddOutput.DisplayName, output.DisplayName)
	assert.Equal(t, aws.String("sns"), output.OutputType)

	snsOutputID = output.OutputID
}

func addPagerDuty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		AddOutput: &models.AddOutputInput{
			UserID:       userID,
			DisplayName:  aws.String("pagerduty-integration"),
			OutputConfig: &models.OutputConfig{PagerDuty: pagerDuty},
		},
	}
	var output models.AddOutputOutput

	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.NotNil(t, output.OutputID)
	assert.Equal(t, input.AddOutput.DisplayName, output.DisplayName)
	assert.Equal(t, aws.String("pagerduty"), output.OutputType)

	pagerDutyOutputID = output.OutputID
}

func addSnsDuplicate(t *testing.T) {
	input := models.LambdaInput{
		AddOutput: &models.AddOutputInput{
			UserID:       userID,
			DisplayName:  aws.String("alert-topic"),
			OutputConfig: &models.OutputConfig{Sns: sns},
		},
	}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("AddOutput failed: already exists: " +
			"A destination with the namealert-topic already exists, please choose another display name"),
		ErrorType:    aws.String("AlreadyExistsError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expected, err)
}

func setDefaultOutput(t *testing.T) {
	input := models.LambdaInput{
		SetDefaultOutputs: &models.SetDefaultOutputsInput{
			Severity:  aws.String("HIGH"),
			OutputIDs: []*string{slackOutputID, pagerDutyOutputID},
		},
	}
	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, nil))
}

func deleteOutputInUse(t *testing.T) {
	input := models.LambdaInput{
		DeleteOutput: &models.DeleteOutputInput{
			OutputID: slackOutputID,
		},
	}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String(
			"DeleteOutput failed: still in use: This destination is currently in use, please try again in a few seconds"),
		ErrorType:    aws.String("InUseError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expected, err)
}

func forceDeleteOutputInUse(t *testing.T) {
	input := models.LambdaInput{
		DeleteOutput: &models.DeleteOutputInput{
			OutputID: pagerDutyOutputID,
			Force:    aws.Bool(true),
		},
	}
	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, nil))

	// Verify the output is deleted
	_, err := getOutputInternal(pagerDutyOutputID)
	require.Error(t, err)
	expectedError := &genericapi.LambdaError{
		ErrorMessage: aws.String(
			"GetOutput failed: does not exist: outputId=" + aws.StringValue(pagerDutyOutputID)),
		ErrorType:    aws.String("DoesNotExistError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expectedError, err)

	//Verify PagerDuty is not listed in the defaults
	outputs, _ := getDefaultOutputsInternal()
	for _, defaultOutput := range outputs.Defaults {
		for _, output := range defaultOutput.OutputIDs {
			if *output == *pagerDutyOutputID {
				assert.Fail(t, "PagerDuty is still present")
			}
		}
	}
}

func updateInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			OutputConfig: &models.OutputConfig{Sns: sns}}}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("UpdateOutput failed: invalid input: " +
			"Key: 'LambdaInput.UpdateOutput.UserID' Error:Field validation for 'UserID' failed on the 'required' tag\n" +
			"Key: 'LambdaInput.UpdateOutput.DisplayName' Error:Field validation for 'DisplayName' failed on the 'required' tag\n" +
			"Key: 'LambdaInput.UpdateOutput.OutputID' Error:Field validation for 'OutputID' failed on the 'required' tag"),
		ErrorType:    aws.String("InvalidInputError"),
		FunctionName: outputsAPI,
	}

	assert.Equal(t, expected, err)
}

func updateSlack(t *testing.T) {
	t.Parallel()
	slack.WebhookURL = aws.String("https://hooks.slack.com/services/DDDDDDDDD/EEEEEEEEE/" +
		"abcdefghijklmnopqrstuvwx")
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			UserID:             userID,
			OutputID:           slackOutputID,
			DisplayName:        aws.String("alert-channel-new"),
			OutputConfig:       &models.OutputConfig{Slack: slack},
			DefaultForSeverity: aws.StringSlice([]string{"CRITICAL"}),
		},
	}
	var output models.UpdateOutputOutput
	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.Equal(t, slackOutputID, output.OutputID)
	assert.Equal(t, aws.String("alert-channel-new"), output.DisplayName)
	assert.Equal(t, slack, output.OutputConfig.Slack)
	assert.Equal(t, aws.String("slack"), output.OutputType)
	assert.Nil(t, output.OutputConfig.Sns)

	defaults, err := getDefaultOutputsInternal()
	require.NoError(t, err)
	expectedDefaultOutputs := &models.DefaultOutputs{
		Severity:  aws.String("CRITICAL"),
		OutputIDs: []*string{slackOutputID},
	}
	assert.Equal(t, []*models.DefaultOutputs{expectedDefaultOutputs}, defaults.Defaults)
}

func updateSns(t *testing.T) {
	t.Parallel()
	sns.TopicArn = aws.String("arn:aws:sns:us-west-2:123456789012:MyTopic")
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			UserID:       userID,
			OutputID:     snsOutputID,
			DisplayName:  aws.String("alert-topic"),
			OutputConfig: &models.OutputConfig{Sns: sns},
		},
	}
	var output models.UpdateOutputOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.Equal(t, snsOutputID, output.OutputID)
	assert.Equal(t, aws.String("alert-topic"), output.DisplayName)
	assert.Equal(t, aws.String("sns"), output.OutputType)
	assert.Equal(t, sns, output.OutputConfig.Sns)
	assert.Nil(t, output.OutputConfig.Slack)
}

func updateSnsEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			UserID:       userID,
			OutputID:     snsOutputID,
			DisplayName:  aws.String("alert-topic-new"),
			OutputConfig: &models.OutputConfig{Sns: sns},
		},
	}
	var output models.UpdateOutputOutput
	assert.Error(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
}

func getSnsEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetOutput: &models.GetOutputInput{
			OutputID: snsOutputID,
		},
	}
	assert.Error(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, nil))
}

func setDefaultOutputDoesntExist(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		SetDefaultOutputs: &models.SetDefaultOutputsInput{
			Severity:  aws.String("HIGH"),
			OutputIDs: []*string{snsOutputID},
		},
	}
	assert.Error(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, nil))
}

func deleteInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{DeleteOutput: &models.DeleteOutputInput{}}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("DeleteOutput failed: invalid input: " +
			"Key: 'LambdaInput.DeleteOutput.OutputID' Error:Field validation for 'OutputID' failed on the 'required' tag"),
		ErrorType:    aws.String("InvalidInputError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expected, err)
}

func deleteSns(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DeleteOutput: &models.DeleteOutputInput{
			OutputID: snsOutputID,
		},
	}
	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, nil))
}

func deleteSnsEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DeleteOutput: &models.DeleteOutputInput{
			OutputID: snsOutputID,
		},
	}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("DeleteOutput failed: does not exist: outputId=" + *snsOutputID),
		ErrorType:    aws.String("DoesNotExistError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expected, err)
}

func getOrganizationOutputs(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{GetOrganizationOutputs: &models.GetOrganizationOutputsInput{}}
	var output models.GetOrganizationOutputsOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))

	// We need to sort the output because order of returned outputItems is not guaranteed by DDB
	sort.Slice(output, func(i, j int) bool {
		return *output[i].OutputType > *output[j].OutputType
	})
	assert.Len(t, output, 3)

	assert.Equal(t, snsOutputID, output[0].OutputID)
	assert.Equal(t, aws.String("sns"), output[0].OutputType)
	assert.Equal(t, userID, output[0].CreatedBy)
	assert.Equal(t, userID, output[0].LastModifiedBy)
	assert.Equal(t, aws.String("alert-topic"), output[0].DisplayName)
	assert.Nil(t, output[0].OutputConfig.Slack)
	assert.Nil(t, output[0].OutputConfig.PagerDuty)
	assert.Equal(t, sns, output[0].OutputConfig.Sns)
	assert.Equal(t, []*string{}, output[0].DefaultForSeverity)

	assert.Equal(t, slackOutputID, output[1].OutputID)
	assert.Equal(t, aws.String("slack"), output[1].OutputType)
	assert.Equal(t, userID, output[1].CreatedBy)
	assert.Equal(t, userID, output[1].LastModifiedBy)
	assert.Equal(t, aws.String("alert-channel"), output[1].DisplayName)
	assert.Nil(t, output[1].OutputConfig.Sns)
	assert.Nil(t, output[1].OutputConfig.PagerDuty)
	assert.Equal(t, slack, output[1].OutputConfig.Slack)
	assert.Equal(t, aws.StringSlice([]string{"HIGH"}), output[1].DefaultForSeverity)

	assert.Equal(t, pagerDutyOutputID, output[2].OutputID)
	assert.Equal(t, aws.String("pagerduty"), output[2].OutputType)
	assert.Equal(t, userID, output[2].CreatedBy)
	assert.Equal(t, userID, output[2].LastModifiedBy)
	assert.Equal(t, aws.String("pagerduty-integration"), output[2].DisplayName)
	assert.Nil(t, output[2].OutputConfig.Slack)
	assert.Nil(t, output[2].OutputConfig.Sns)
	assert.Equal(t, pagerDuty, output[2].OutputConfig.PagerDuty)
	assert.Equal(t, aws.StringSlice([]string{"HIGH"}), output[2].DefaultForSeverity)
}

func getOutput(t *testing.T) {
	t.Parallel()

	output, err := getOutputInternal(snsOutputID)

	require.NoError(t, err)
	assert.Equal(t, snsOutputID, output.OutputID)
	assert.Equal(t, snsType, output.OutputType)
	assert.Equal(t, userID, output.CreatedBy)
	assert.Equal(t, userID, output.LastModifiedBy)
	assert.Equal(t, aws.String("alert-topic"), output.DisplayName)
	assert.Nil(t, output.OutputConfig.Slack)
	assert.Equal(t, sns, output.OutputConfig.Sns)
	assert.Equal(t, []*string{}, output.DefaultForSeverity)
}

func getDefaults(t *testing.T) {
	t.Parallel()

	expectedResult := models.GetDefaultOutputsOutput{
		Defaults: []*models.DefaultOutputs{
			{
				Severity:  aws.String("HIGH"),
				OutputIDs: []*string{slackOutputID, pagerDutyOutputID},
			},
		},
	}

	outputs, err := getDefaultOutputsInternal()
	require.NoError(t, err)
	require.Len(t, outputs.Defaults, 1)

	ids := outputs.Defaults[0].OutputIDs
	sort.Slice(ids, func(i, j int) bool {
		return *(ids[i]) < *(ids[j])
	})
	ids = expectedResult.Defaults[0].OutputIDs
	sort.Slice(ids, func(i, j int) bool {
		return *(ids[i]) < *(ids[j])
	})

	assert.Equal(t, expectedResult, outputs)
}

func getDefaultOutputsInternal() (models.GetDefaultOutputsOutput, error) {
	input := models.LambdaInput{
		GetDefaultOutputs: &models.GetDefaultOutputsInput{},
	}
	var output models.GetDefaultOutputsOutput
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &output)
	return output, err
}

func getOutputInternal(outputID *string) (models.GetOutputOutput, error) {
	input := models.LambdaInput{
		GetOutput: &models.GetOutputInput{OutputID: outputID},
	}

	var output models.GetOutputOutput
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &output)
	return output, err
}
