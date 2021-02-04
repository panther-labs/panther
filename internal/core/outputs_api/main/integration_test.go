package main

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
	outputsAPI = "panther-outputs-api"
	tableName  = "panther-outputs"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	lambdaClient    = lambda.New(awsSession)

	slack = &models.SlackConfig{
		WebhookURL: "https://hooks.slack.com/services/AAAAAAAAA/BBBBBBBBB/" +
			"abcdefghijklmnopqrstuvwx",
	}
	sns       = &models.SnsConfig{TopicArn: "arn:aws:sns:us-west-2:123456789012:MyTopic"}
	pagerDuty = &models.PagerDutyConfig{IntegrationKey: "7a08481fbc0746c9a8a487f90d737e05"}
	gitHub    = &models.GithubConfig{
		RepoName: "myRepo",
		Token:    "abc123",
	}
	snsType = aws.String("sns")
	userID  = aws.String("43808de4-fbae-4f90-a9b4-1e4982d65287")

	// Remember the generated output IDs
	slackOutputID     *string
	snsOutputID       *string
	pagerDutyOutputID *string
	gitHubOutputID    *string
	redacted          = ""
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

	// Add one of each output type in parallel.
	t.Run("Add", func(t *testing.T) {
		t.Run("AddInvalid", addInvalid)
		t.Run("AddSlack", addSlack)
		t.Run("AddSns", addSns)
		t.Run("AddGitHub", addGitHub)
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

	// Get outputs in parallel
	t.Run("Get", func(t *testing.T) {
		t.Run("GetOutputs", getOutputs)
		t.Run("GetOutputsWithSecrets", getOutputsWithSecrets)
		t.Run("GetOutput", getOutput)
	})
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

	// Perform a partial update and then verify that secrets aren't changed
	t.Run("PartialUpdate", func(t *testing.T) {
		t.Run("PartialUpdateDisplayName", partialUpdateDisplayName)
		t.Run("PartialUpdateConfig", partialUpdateConfig)
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
		// nolint:lll
		ErrorMessage: aws.String("DisplayName invalid, failed to satisfy the condition: required"),
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
	assert.Equal(t, aws.StringSlice([]string{"HIGH"}), output.DefaultForSeverity)

	slackOutputID = output.OutputID
}

func addGitHub(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		AddOutput: &models.AddOutputInput{
			UserID:             userID,
			DisplayName:        aws.String("git-issues"),
			OutputConfig:       &models.OutputConfig{Github: gitHub},
			DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
		},
	}
	var output models.AddOutputOutput
	assert.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.NotNil(t, output.OutputID)
	assert.Equal(t, aws.String("git-issues"), output.DisplayName)
	assert.Equal(t, aws.String("github"), output.OutputType)
	assert.Equal(t, aws.StringSlice([]string{"HIGH"}), output.DefaultForSeverity)

	gitHubOutputID = output.OutputID
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
		ErrorMessage: aws.String(
			"A destination with the namealert-topic already exists, please choose another display name"),
		ErrorType:    aws.String("AlreadyExistsError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expected, err)
}

func updateInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			OutputConfig: &models.OutputConfig{Sns: sns}}}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("UserID invalid, failed to satisfy the condition: required"),
		ErrorType:    aws.String("InvalidInputError"),
		FunctionName: outputsAPI,
	}

	assert.Equal(t, expected, err)
}

func updateSlack(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			UserID:             userID,
			OutputID:           slackOutputID,
			DisplayName:        aws.String("alert-channel-new"),
			DefaultForSeverity: aws.StringSlice([]string{"CRITICAL"}),
		},
	}
	var output models.UpdateOutputOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))

	expected := models.UpdateOutputOutput{
		AlertTypes:         []string{"RULE", "RULE_ERROR", "POLICY"},
		CreatedBy:          userID,
		CreationTime:       output.CreationTime,
		DefaultForSeverity: input.UpdateOutput.DefaultForSeverity,
		DisplayName:        input.UpdateOutput.DisplayName,
		LastModifiedBy:     userID,
		LastModifiedTime:   output.LastModifiedTime,
		OutputConfig: &models.OutputConfig{
			Slack: &models.SlackConfig{WebhookURL: ""},
		}, // no webhook URL in response
		OutputID:   slackOutputID,
		OutputType: aws.String("slack"),
	}
	assert.Equal(t, expected, output)
}

func updateSns(t *testing.T) {
	t.Parallel()
	sns.TopicArn = "arn:aws:sns:us-west-2:123456789012:MyTopic"
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

func partialUpdateDisplayName(t *testing.T) {
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			UserID:       userID,
			OutputID:     pagerDutyOutputID,
			DisplayName:  aws.String("pagerduty-integration-updated"),
			OutputConfig: nil, // Don't set an output config at all
		},
	}
	var output models.UpdateOutputOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.Equal(t, pagerDutyOutputID, output.OutputID)
	assert.Equal(t, aws.String("pagerduty-integration-updated"), output.DisplayName)
	assert.Equal(t, aws.String("pagerduty"), output.OutputType)
	assert.Equal(t, redacted, output.OutputConfig.PagerDuty.IntegrationKey)
	assert.Nil(t, output.OutputConfig.Slack)

	// Verify that the secrets didn't change
	withSecrets, err := getOutputWithSecretsInternal(pagerDutyOutputID)
	require.NoError(t, err)
	assert.Equal(t, withSecrets.OutputConfig.PagerDuty.IntegrationKey, pagerDuty.IntegrationKey)
}

func partialUpdateConfig(t *testing.T) {
	input := models.LambdaInput{
		UpdateOutput: &models.UpdateOutputInput{
			UserID:      userID,
			OutputID:    gitHubOutputID,
			DisplayName: aws.String("git-issues"),
			OutputConfig: &models.OutputConfig{
				Github: &models.GithubConfig{
					// RepoName: nil, don't set the repo name
					Token: "xyz897",
				},
			},
		},
	}
	var output models.UpdateOutputOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &output))
	assert.Equal(t, gitHubOutputID, output.OutputID)
	assert.Equal(t, aws.String("git-issues"), output.DisplayName)
	assert.Equal(t, aws.String("github"), output.OutputType)
	// Token should be redacted
	assert.Equal(t, redacted, output.OutputConfig.Github.Token)
	// Repo name should not be updated
	assert.Equal(t, gitHub.RepoName, output.OutputConfig.Github.RepoName)
	assert.Nil(t, output.OutputConfig.Slack)

	// Verify that the secrets changed
	withSecrets, err := getOutputWithSecretsInternal(gitHubOutputID)
	require.NoError(t, err)
	assert.Equal(t, withSecrets.OutputConfig.Github.Token, input.UpdateOutput.OutputConfig.Github.Token)
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

func deleteInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{DeleteOutput: &models.DeleteOutputInput{}}
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("OutputID invalid, failed to satisfy the condition: required"),
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
		ErrorMessage: aws.String("outputId=" + *snsOutputID + " does not exist"),
		ErrorType:    aws.String("DoesNotExistError"),
		FunctionName: outputsAPI,
	}
	assert.Equal(t, expected, err)
}

func getOutputs(t *testing.T) {
	t.Parallel()
	verifyListOutputs(t, false)
}

func getOutputsWithSecrets(t *testing.T) {
	t.Parallel()
	verifyListOutputs(t, true)
}

func verifyListOutputs(t *testing.T, withSecrets bool) {
	var input models.LambdaInput
	if withSecrets {
		input.GetOutputsWithSecrets = &models.GetOutputsWithSecretsInput{}
	} else {
		input.GetOutputs = &models.GetOutputsInput{}
	}

	var outputs models.GetOutputsOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, outputsAPI, &input, &outputs))

	// We need to sort the output because order of returned outputItems is not guaranteed by DDB
	sort.Slice(outputs, func(i, j int) bool {
		return *outputs[i].OutputType > *outputs[j].OutputType
	})
	assert.Len(t, outputs, 4)

	// Verify timestamps and ids since we don't know their value ahead of time
	for _, output := range outputs {
		assert.NotNil(t, output.CreationTime)
		assert.NotNil(t, output.OutputID)
	}

	expected := models.GetOutputsOutput{
		{
			AlertTypes:         []string{"RULE", "RULE_ERROR", "POLICY"},
			CreatedBy:          userID,
			CreationTime:       outputs[0].CreationTime,
			DefaultForSeverity: []*string{},
			DisplayName:        aws.String("alert-topic"),
			LastModifiedBy:     userID,
			LastModifiedTime:   outputs[0].LastModifiedTime,
			OutputID:           outputs[0].OutputID,
			OutputType:         aws.String("sns"),
			OutputConfig:       &models.OutputConfig{Sns: sns},
		},
		{
			AlertTypes:         []string{"RULE", "RULE_ERROR", "POLICY"},
			CreatedBy:          userID,
			CreationTime:       outputs[1].CreationTime,
			DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
			DisplayName:        aws.String("alert-channel"),
			LastModifiedBy:     userID,
			LastModifiedTime:   outputs[1].LastModifiedTime,
			OutputID:           outputs[1].OutputID,
			OutputType:         aws.String("slack"),
			OutputConfig:       &models.OutputConfig{Slack: slack},
		},
		{
			AlertTypes:         []string{"RULE", "RULE_ERROR", "POLICY"},
			CreatedBy:          userID,
			CreationTime:       outputs[2].CreationTime,
			DefaultForSeverity: []*string{},
			DisplayName:        aws.String("pagerduty-integration"),
			LastModifiedBy:     userID,
			LastModifiedTime:   outputs[2].LastModifiedTime,
			OutputID:           outputs[2].OutputID,
			OutputType:         aws.String("pagerduty"),
			OutputConfig:       &models.OutputConfig{PagerDuty: pagerDuty},
		},
		{
			AlertTypes:         []string{"RULE", "RULE_ERROR", "POLICY"},
			CreatedBy:          userID,
			CreationTime:       outputs[3].CreationTime,
			DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
			DisplayName:        aws.String("git-issues"),
			LastModifiedBy:     userID,
			LastModifiedTime:   outputs[3].LastModifiedTime,
			OutputID:           outputs[3].OutputID,
			OutputType:         aws.String("github"),
			OutputConfig:       &models.OutputConfig{Github: gitHub},
		},
	}

	if !withSecrets {
		// Credentials are obfuscated
		expected[1].OutputConfig.Slack = &models.SlackConfig{
			WebhookURL: redacted,
		}
		expected[2].OutputConfig.PagerDuty = &models.PagerDutyConfig{
			IntegrationKey: redacted,
		}
		expected[3].OutputConfig.Github = &models.GithubConfig{
			RepoName: gitHub.RepoName,
			Token:    redacted,
		}
	}

	assert.Equal(t, expected, outputs)
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

func getOutputInternal(outputID *string) (models.GetOutputOutput, error) {
	input := models.LambdaInput{
		GetOutput: &models.GetOutputInput{OutputID: outputID},
	}

	var output models.GetOutputOutput
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &output)
	return output, err
}

func getOutputWithSecretsInternal(outputID *string) (*models.AlertOutput, error) {
	input := models.LambdaInput{
		GetOutputsWithSecrets: &models.GetOutputsWithSecretsInput{},
	}

	var outputs models.GetOutputsOutput
	err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &outputs)
	for _, output := range outputs {
		if *output.OutputID == *outputID {
			return output, nil
		}
	}
	return nil, err
}
