package aws

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestLambdaFunctionsList(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvc([]string{"ListFunctionsPages"})

	out := listFunctions(mockSvc)
	assert.NotEmpty(t, out)
}

func TestLambdaFunctionsListError(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvcError([]string{"ListFunctionsPages"})

	out := listFunctions(mockSvc)
	assert.Nil(t, out)
}

func TestLambdaFunctionListTags(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvc([]string{"ListTags"})

	out, err := listTagsLambda(mockSvc, awstest.ExampleFunctionName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestLambdaFunctionListTagsError(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvcError([]string{"ListTags"})

	out, err := listTagsLambda(mockSvc, awstest.ExampleFunctionName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestLambdaFunctionGetPolicy(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvc([]string{"GetPolicy"})

	out, err := getPolicy(mockSvc, awstest.ExampleFunctionName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestLambdaFunctionGetPolicyError(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvcError([]string{"GetPolicy"})

	out, err := getPolicy(mockSvc, awstest.ExampleFunctionName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestBuildLambdaFunctionSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvcAll()

	lambdaSnapshot := buildLambdaFunctionSnapshot(
		mockSvc,
		awstest.ExampleListFunctions.Functions[0],
	)

	assert.NotEmpty(t, lambdaSnapshot.Tags)
	assert.NotEmpty(t, lambdaSnapshot.Policy)
	assert.Equal(t, "arn:aws:lambda:us-west-2:123456789012:function:ExampleFunction", *lambdaSnapshot.ARN)
	assert.Equal(t, awstest.ExampleFunctionConfiguration.TracingConfig, lambdaSnapshot.TracingConfig)
}

func TestBuildLambdaFunctionSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvcAllError()

	lambdaSnapshot := buildLambdaFunctionSnapshot(
		mockSvc,
		awstest.ExampleListFunctions.Functions[0],
	)

	assert.NotNil(t, lambdaSnapshot)
	assert.Nil(t, lambdaSnapshot.Policy)
	assert.Nil(t, lambdaSnapshot.Tags)
}

func TestLambdaFunctionPoller(t *testing.T) {
	awstest.MockLambdaForSetup = awstest.BuildMockLambdaSvcAll()

	LambdaClientFunc = awstest.SetupMockLambda

	resources, err := PollLambdaFunctions(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resources)
}

func TestLambdaFunctionPollerError(t *testing.T) {
	awstest.MockLambdaForSetup = awstest.BuildMockLambdaSvcAllError()

	LambdaClientFunc = awstest.SetupMockLambda

	resources, err := PollLambdaFunctions(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
}
