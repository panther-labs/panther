package main

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	policyEngineName       = "panther-policy-engine"
	rulesEngineName        = "panther-rules-engine"
	globalLayerName        = "panther-engine-globals"
	layerManagerLambdaName = "panther-layer-manager"
	analysisTableName      = "panther-analysis"

	// The test global
	globalAnalysisID          = "panther"
	globalAnalysisBody        = "def custom_always_true():\n\treturn True"
	globalAnalysisBodyUpdated = "def custom_always_true():\n\treturn True\n\ndef more_logic():\n\treturn False"
)

var (
	integrationTest bool
	lambdaClient    lambdaiface.LambdaAPI
	dynamoClient    dynamodbiface.DynamoDBAPI

	// The ARN of the global layer
	globalLayerArn *string
	// The ARN with version of the global layer attached to the policy/rule engine
	globalLayerVersionArn *string
	// The layer attached to the policy/rule engine
	globalLayerVersion                    *lambda.GetLayerVersionByArnOutput
	policyEngineConfig, rulesEngineConfig *lambda.FunctionConfiguration
	payload                               []byte
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	os.Exit(m.Run())
}

// TestIntegrationLayerManager is the single integration test
func TestIntegrationLayerManager(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	// Due to positioning/naming, this test will always run immediately after the analysis-api tests. This means the
	// layer-manager queue may already have some requests staged from those tests that haven't been resolved, which can
	// mess up these tests. Wait a few seconds to let them all shake out. In real life operations this is not an
	// issue because the lambda will just fail and then retry some time later and succeed, but we don't want to
	// have to mess around with that in integration tests.
	time.Sleep(5 * time.Second)

	err := setup()
	require.NoError(t, err)

	t.Run("TestInitialSetup", func(t *testing.T) {
		t.Run("TestInitialSetup", testInitialSetup)
	})

	if t.Failed() {
		return
	}

	// Get the current global layer version
	globalLayerVersion, err = lambdaClient.GetLayerVersionByArn(&lambda.GetLayerVersionByArnInput{Arn: globalLayerVersionArn})
	require.NoError(t, err)

	t.Run("TestNoChanges", func(t *testing.T) {
		t.Run("TestUpdateNoChange", testUpdateNoChange)
	})

	if t.Failed() {
		return
	}

	// Change the layer body in the analysis table
	err = writeTestGlobal(globalAnalysisBodyUpdated)
	require.NoError(t, err)

	t.Run("TestChanges", func(t *testing.T) {
		t.Run("TestUpdateChange", testUpdateChange)
	})

	if t.Failed() {
		return
	}

	// Delete the global
	_, err = dynamoClient.DeleteItem(&dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String(globalAnalysisID)},
		},
		TableName: aws.String(analysisTableName),
	})
	require.NoError(t, err)

	t.Run("TestDelete", func(t *testing.T) {
		t.Run("TestDeleteLayer", testDeleteLayer)
	})
}

// setup clears away all previous configurations so the test can be run clean, and sets up the things that the tests
// will be expecting.
func setup() (err error) {
	// Setup the payload that will be re-used to invoke the layer-manager lambda
	payload, err = jsoniter.Marshal(events.SQSEvent{
		Records: []events.SQSMessage{
			{
				Body: "GLOBAL",
			},
		},
	})
	if err != nil {
		return err
	}

	awsSession := session.Must(session.NewSession())
	lambdaClient = lambda.New(awsSession)
	dynamoClient = dynamodb.New(awsSession)
	// Clear the analysis table to remove any existing globals
	err = testutils.ClearDynamoTable(awsSession, analysisTableName)
	if err != nil {
		return err
	}

	// Remove any existing global layer from the policy/rule engines
	policyConfig, err := lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(policyEngineName),
	})
	if err != nil {
		return err
	}
	newLayers, err := removeLayerFromList(globalLayerName, policyConfig.Layers)
	if err != nil {
		return nil
	}
	_, err = lambdaClient.UpdateFunctionConfiguration(&lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(policyEngineName),
		Layers:       newLayers,
	})
	if err != nil {
		return err
	}

	rulesConfig, err := lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(rulesEngineName),
	})
	if err != nil {
		return err
	}
	newLayers, err = removeLayerFromList(globalLayerName, rulesConfig.Layers)
	if err != nil {
		return nil
	}
	_, err = lambdaClient.UpdateFunctionConfiguration(&lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(rulesEngineName),
		Layers:       newLayers,
	})
	if err != nil {
		return err
	}

	// Store a test global in the analysis-table for the layer-manager to find
	return writeTestGlobal(globalAnalysisBody)
}

// writeTestGlobal updates the analysis-table without using the analysis-api (which will automatically trigger
// the layer-manager, which we want to control)
func writeTestGlobal(testBody string) error {
	// Construct the test global
	global := struct {
		Body string `json:"body"`
		ID   string `json:"id"`
		Type string `json:"type"`
	}{Body: testBody, ID: globalAnalysisID, Type: "GLOBAL"}
	globalDynamoItem, err := dynamodbattribute.MarshalMap(global)
	if err != nil {
		return err
	}

	// Write the test global to dynamo
	_, err = dynamoClient.PutItem(&dynamodb.PutItemInput{Item: globalDynamoItem, TableName: aws.String(analysisTableName)})
	if err != nil {
		return err
	}

	return nil
}

// removeLayerFromList takes a single layer out of a list of layers based on layer name, because initially we only
// know a layer by it's name but lambda will only refer to a layer by it's ARN
func removeLayerFromList(layerName string, layers []*lambda.Layer) ([]*string, error) {
	var newLayers []*string
	// format: arn:aws:lambda:us-west-2:123456789012:layer:panther-engine-globals:XX
	layerResourceName := "layer:" + layerName + ":"
	for _, layer := range layers {
		parsedLayerArn, err := arn.Parse(aws.StringValue(layer.Arn))
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(parsedLayerArn.Resource, layerResourceName) {
			newLayers = append(newLayers, layer.Arn)
		}
	}
	return newLayers, nil
}

// Tests the behavior when no global module exists, then one is created
func testInitialSetup(t *testing.T) {
	response, err := lambdaClient.Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(layerManagerLambdaName),
		Payload:      payload,
	})
	require.NoError(t, err)
	require.Nil(t, response.FunctionError)

	// Find the new global layer ARN (and store it for reference by other tests)
	layers, err := lambdaClient.ListLayers(&lambda.ListLayersInput{})
	require.NoError(t, err)
	for _, layer := range layers.Layers {
		if aws.StringValue(layer.LayerName) == globalLayerName {
			globalLayerArn = layer.LayerArn
			globalLayerVersionArn = layer.LatestMatchingVersion.LayerVersionArn
		}
	}
	// Test that the layer got created
	require.NotNil(t, globalLayerArn)
	require.NotNil(t, globalLayerVersionArn)

	// Verify that the policy & rule engine have been updated with this new layer
	newPolicyConfig, err := lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(policyEngineName),
	})
	require.NoError(t, err)

	var policyLayerVersionArn *string
	for _, layer := range newPolicyConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			policyLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the new layer is attached and at the correct version
	require.NotNil(t, policyLayerVersionArn)
	assert.Equal(t, globalLayerVersionArn, policyLayerVersionArn)

	newRulesConfig, err := lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(rulesEngineName),
	})
	require.NoError(t, err)
	var ruleLayerVersionArn *string
	for _, layer := range newRulesConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			ruleLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the new layer is attached and at the correct version
	require.NotNil(t, ruleLayerVersionArn)
	assert.Equal(t, aws.StringValue(globalLayerVersionArn), aws.StringValue(ruleLayerVersionArn))
}

// Tests the behavior when a layer update is requested but nothing changed
func testUpdateNoChange(t *testing.T) {
	// Invoke the lambda function when there should be no change
	response, err := lambdaClient.Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(layerManagerLambdaName),
		Payload:      payload,
	})
	require.NoError(t, err)
	require.Nil(t, response.FunctionError)

	// Find the new layer configuration
	newLayers, err := lambdaClient.ListLayers(&lambda.ListLayersInput{})
	require.NoError(t, err)
	var newLayerArn *string
	for _, layer := range newLayers.Layers {
		if aws.StringValue(layer.LayerName) == globalLayerName {
			newLayerArn = layer.LatestMatchingVersion.LayerVersionArn
		}
	}
	require.NotNil(t, newLayerArn)

	newLayerVersion, err := lambdaClient.GetLayerVersionByArn(&lambda.GetLayerVersionByArnInput{Arn: newLayerArn})
	require.NoError(t, err)

	// Verify that the new and old layers match on code, but have different versions
	assert.Equal(t, globalLayerVersion.Content.CodeSha256, newLayerVersion.Content.CodeSha256)
	assert.Equal(t, globalLayerVersion.Content.CodeSize, newLayerVersion.Content.CodeSize)
	assert.Less(t, aws.Int64Value(globalLayerVersion.Version), aws.Int64Value(newLayerVersion.Version))

	// Verify that the old layer version has been deleted
	versions, err := lambdaClient.ListLayerVersions(&lambda.ListLayerVersionsInput{
		LayerName: aws.String(globalLayerName),
	})
	require.NoError(t, err)
	for _, version := range versions.LayerVersions {
		assert.NotEqual(t, globalLayerVersionArn, version.LayerVersionArn)
	}

	// Store the new configurations
	globalLayerArn = newLayerArn
	globalLayerVersionArn = newLayerVersion.LayerVersionArn
	globalLayerVersion = newLayerVersion

	// Verify that the policy & rule engine have been updated with this new layer version
	policyEngineConfig, err = lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(policyEngineName),
	})
	require.NoError(t, err)

	var policyLayerVersionArn *string
	for _, layer := range policyEngineConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			policyLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the new layer is attached and at the correct version
	require.NotNil(t, policyLayerVersionArn)
	assert.Equal(t, aws.StringValue(globalLayerVersionArn), aws.StringValue(policyLayerVersionArn))

	rulesEngineConfig, err = lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(rulesEngineName),
	})
	require.NoError(t, err)
	var ruleLayerVersionArn *string
	for _, layer := range rulesEngineConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			ruleLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the new layer is attached and at the correct version
	require.NotNil(t, ruleLayerVersionArn)
	assert.Equal(t, aws.StringValue(globalLayerVersionArn), aws.StringValue(ruleLayerVersionArn))
}

// Tests the behavior when a layer update is requested after the global has changed
func testUpdateChange(t *testing.T) {
	// Invoke the lambda function when there should be a change
	response, err := lambdaClient.Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(layerManagerLambdaName),
		Payload:      payload,
	})
	require.NoError(t, err)
	require.Nil(t, response.FunctionError)

	// Find the new layer configuration
	newLayers, err := lambdaClient.ListLayers(&lambda.ListLayersInput{})
	require.NoError(t, err)
	var newLayerArn *string
	for _, layer := range newLayers.Layers {
		if aws.StringValue(layer.LayerName) == globalLayerName {
			newLayerArn = layer.LatestMatchingVersion.LayerVersionArn
		}
	}
	require.NotNil(t, newLayerArn)

	newLayerVersion, err := lambdaClient.GetLayerVersionByArn(&lambda.GetLayerVersionByArnInput{Arn: newLayerArn})
	require.NoError(t, err)

	// Verify that the new and old layers have different hashes, size, and versions
	assert.NotEqual(t, globalLayerVersion.Content.CodeSha256, newLayerVersion.Content.CodeSha256)
	assert.NotEqual(t, globalLayerVersion.Content.CodeSize, newLayerVersion.Content.CodeSize)
	assert.Less(t, aws.Int64Value(globalLayerVersion.Version), aws.Int64Value(newLayerVersion.Version))

	// Verify that the old layer version has been deleted
	versions, err := lambdaClient.ListLayerVersions(&lambda.ListLayerVersionsInput{
		LayerName: aws.String(globalLayerName),
	})
	require.NoError(t, err)
	for _, version := range versions.LayerVersions {
		assert.NotEqual(t, globalLayerVersionArn, version.LayerVersionArn)
	}

	// Store the new configurations
	globalLayerArn = newLayerArn
	globalLayerVersionArn = newLayerVersion.LayerVersionArn
	globalLayerVersion = newLayerVersion

	// Verify that the policy & rule engine have been updated with this new layer
	policyEngineConfig, err = lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(policyEngineName),
	})
	require.NoError(t, err)

	var policyLayerVersionArn *string
	for _, layer := range policyEngineConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			policyLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the new layer is attached and at the correct version
	require.NotNil(t, policyLayerVersionArn)
	assert.Equal(t, aws.StringValue(globalLayerVersionArn), aws.StringValue(policyLayerVersionArn))

	rulesEngineConfig, err = lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(rulesEngineName),
	})
	require.NoError(t, err)
	var ruleLayerVersionArn *string
	for _, layer := range rulesEngineConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			ruleLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the new layer is attached and at the correct version
	require.NotNil(t, ruleLayerVersionArn)
	assert.Equal(t, aws.StringValue(globalLayerVersionArn), aws.StringValue(ruleLayerVersionArn))
}

// Tests the behavior when a layer needs to be deleted
func testDeleteLayer(t *testing.T) {
	// Invoke the lambda function when there are no globals configured
	response, err := lambdaClient.Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(layerManagerLambdaName),
		Payload:      payload,
	})
	require.NoError(t, err)
	require.Nil(t, response.FunctionError)

	// Find the new layer configuration
	newLayers, err := lambdaClient.ListLayers(&lambda.ListLayersInput{})
	require.NoError(t, err)
	var newLayerArn *string
	for _, layer := range newLayers.Layers {
		if aws.StringValue(layer.LayerName) == globalLayerName {
			newLayerArn = layer.LatestMatchingVersion.LayerVersionArn
		}
	}
	// We should not have found the layer
	require.Nil(t, newLayerArn)

	// Since we've verified that the layer is deleted, we now need to verify that the policy & rule engine have
	// been updated to not include this layer
	policyEngineConfig, err = lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(policyEngineName),
	})
	require.NoError(t, err)

	var policyLayerVersionArn *string
	for _, layer := range policyEngineConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			policyLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the layer is not attached
	require.Nil(t, policyLayerVersionArn)

	rulesEngineConfig, err = lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(rulesEngineName),
	})
	require.NoError(t, err)
	var ruleLayerVersionArn *string
	for _, layer := range rulesEngineConfig.Layers {
		if strings.HasPrefix(aws.StringValue(layer.Arn), aws.StringValue(globalLayerArn)) {
			ruleLayerVersionArn = layer.Arn
			break
		}
	}
	// Verify that the new layer is not attached
	require.Nil(t, ruleLayerVersionArn)
}
