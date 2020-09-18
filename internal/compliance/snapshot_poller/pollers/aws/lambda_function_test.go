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

	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestLambdaFunctionsList(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvc([]string{"ListFunctionsPages"})

	out, marker, err := listFunctions(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestFunctionListIterator(t *testing.T) {
	var functions []*lambda.FunctionConfiguration
	var marker *string

	cont := functionIterator(awstest.ExampleListFunctions, &functions, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, functions, 1)

	for i := 1; i < 50; i++ {
		cont = functionIterator(awstest.ExampleListFunctionsContinue, &functions, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, functions, 1+i*2)
	}

	cont = functionIterator(awstest.ExampleListFunctionsContinue, &functions, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, functions, 101)
}

func TestLambdaFunctionsListError(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvcError([]string{"ListFunctionsPages"})

	out, marker, err := listFunctions(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
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

	lambdaSnapshot, err := buildLambdaFunctionSnapshot(
		mockSvc,
		awstest.ExampleListFunctions.Functions[0],
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, lambdaSnapshot.Tags)
	assert.NotEmpty(t, lambdaSnapshot.Policy)
	assert.Equal(t, "arn:aws:lambda:us-west-2:123456789012:function:ExampleFunction", *lambdaSnapshot.ARN)
	assert.Equal(t, awstest.ExampleFunctionConfiguration.TracingConfig, lambdaSnapshot.TracingConfig)
}

func TestBuildLambdaFunctionSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockLambdaSvcAllError()

	lambdaSnapshot, err := buildLambdaFunctionSnapshot(
		mockSvc,
		awstest.ExampleListFunctions.Functions[0],
	)

	assert.Error(t, err)
	assert.Nil(t, lambdaSnapshot)
}

func TestLambdaFunctionPoller(t *testing.T) {
	awstest.MockLambdaForSetup = awstest.BuildMockLambdaSvcAll()

	LambdaClientFunc = awstest.SetupMockLambda

	resources, marker, err := PollLambdaFunctions(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NotEmpty(t, resources)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestLambdaFunctionPollerError(t *testing.T) {
	resetCache()
	awstest.MockLambdaForSetup = awstest.BuildMockLambdaSvcAllError()

	LambdaClientFunc = awstest.SetupMockLambda

	resources, marker, err := PollLambdaFunctions(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
	assert.Nil(t, marker)
	assert.Error(t, err)
}
