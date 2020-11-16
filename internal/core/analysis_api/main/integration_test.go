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
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	tableName           = "panther-analysis"
	analysesRoot        = "./test_analyses"
	analysesZipLocation = "./bulk_upload.zip"
)

var (
	integrationTest bool
	apiClient       gatewayapi.API

	userID = "521a1c7b-273f-4a03-99a7-5c661de5b0e8"

	// NOTE: this gets changed by the bulk upload!
	policy = &models.Policy{
		CoreEntry: models.CoreEntry{
			Description: "Matches every resource",
			ID:          "Test:Policy",
			Tags:        []string{"policyTag"},
		},
		PythonDetection: models.PythonDetection{
			DisplayName: "AlwaysTrue",
			Enabled:     true,
			OutputIDs:   []string{"policyOutput"},
			Reports:     map[string][]string{},
			Severity:    compliancemodels.SeverityMedium,
			Tests: []models.UnitTest{
				{
					Name:           "This will be True",
					ExpectedResult: true,
					Resource:       `{}`,
				},
				{
					Name:           "This will also be True",
					ExpectedResult: true,
					Resource:       `{"nested": {}}`,
				},
			},
		},
		AutoRemediationParameters: map[string]string{},
		ResourceTypes:             []string{},
		Suppressions:              []string{},
	}
	versionedPolicy *models.Policy // this will get set when we modify policy for use in delete testing

	// Set during bulk upload
	policyFromBulk = &models.Policy{
		CoreEntry: models.CoreEntry{
			ID: "AWS.CloudTrail.Log.Validation.Enabled",
		},
	}
	policyFromBulkJSON = &models.Policy{
		CoreEntry: models.CoreEntry{
			ID: "Test:Policy:JSON",
		},
	}

	rule = &models.Rule{
		CoreEntry: models.CoreEntry{
			Body:        "def rule(event): return len(event) > 0\n",
			Description: "Matches every non-empty event",
			ID:          "NonEmptyEvent",
			Tags:        []string{"test-tag"},
		},
		PythonDetection: models.PythonDetection{
			DisplayName: "",
			Enabled:     true,
			OutputIDs:   []string{"test-output1", "test-output2"},
			Reference:   "",
			Reports:     map[string][]string{},
			Runbook:     "",
			Severity:    compliancemodels.SeverityHigh,
			Tests:       []models.UnitTest{},
		},
		DedupPeriodMinutes: 1440,
		LogTypes:           []string{"AWS.CloudTrail"},
		Threshold:          10,
	}

	global = &models.Global{
		CoreEntry: models.CoreEntry{
			Body:        "def helper_is_true(truthy): return truthy is True\n",
			Description: "Provides a helper function",
			ID:          "GlobalTypeAnalysis",
		},
	}

	dataModel = &models.DataModel{
		CoreEntry: models.CoreEntry{
			Body:        "def get_source_ip(event): return 'source_ip'\n",
			Description: "Example LogType Schema",
			ID:          "DataModelTypeAnalysis",
			Tags:        []string{},
		},
		Enabled:  true,
		LogTypes: []string{"OneLogin.Events"},
		Mappings: []models.DataModelMapping{
			{
				Name: "source_ip",
				Path: "ipAddress",
			},
		},
	}
	dataModelTwo = &models.DataModel{
		CoreEntry: models.CoreEntry{
			Body:        "def get_source_ip(event): return 'source_ip'\n",
			Description: "Example LogType Schema",
			ID:          "SecondDataModelTypeAnalysis",
			Tags:        []string{},
		},
		Enabled:  true,
		LogTypes: []string{"Box.Events"},
		Mappings: []models.DataModelMapping{
			{
				Name: "source_ip",
				Path: "ipAddress",
			},
		},
	}
	dataModels           = [2]*models.DataModel{dataModel, dataModelTwo}
	dataModelFromBulkYML = &models.DataModel{
		CoreEntry: models.CoreEntry{
			ID:   "Some.Events.DataModel",
			Tags: []string{},
		},
		Enabled:  true,
		LogTypes: []string{"Some.Events"},
		Mappings: []models.DataModelMapping{
			{
				Name: "source_ip",
				Path: "ipAddress",
			},
			{
				Name: "dest_ip",
				Path: "destAddress",
			},
		},
	}
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	os.Exit(m.Run())
}

// TestIntegrationAPI is the single integration test - invokes the live API Gateway.
func TestIntegrationAPI(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	awsSession := session.Must(session.NewSession())
	apiClient = gatewayapi.NewClient(lambda.New(awsSession), "panther-analysis-api")

	// Set expected bodies from test files
	trueBody, err := ioutil.ReadFile(path.Join(analysesRoot, "policy_always_true.py"))
	require.NoError(t, err)
	policy.Body = string(trueBody)
	policyFromBulkJSON.Body = string(trueBody)

	cloudtrailBody, err := ioutil.ReadFile(path.Join(analysesRoot, "policy_aws_cloudtrail_log_validation_enabled.py"))
	require.NoError(t, err)
	policyFromBulk.Body = string(cloudtrailBody)

	// Lookup analysis bucket name
	cfnClient := cloudformation.New(awsSession)
	response, err := cfnClient.DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String("panther-bootstrap")})
	require.NoError(t, err)
	var bucketName string
	for _, output := range response.Stacks[0].Outputs {
		if aws.StringValue(output.OutputKey) == "AnalysisVersionsBucket" {
			bucketName = *output.OutputValue
			break
		}
	}
	require.NotEmpty(t, bucketName)

	// Reset data stores: S3 bucket and Dynamo table
	require.NoError(t, testutils.ClearS3Bucket(awsSession, bucketName))
	require.NoError(t, testutils.ClearDynamoTable(awsSession, tableName))

	// ORDER MATTERS!

	// In general, each group of tests runs in parallel
	t.Run("TestPolicies", func(t *testing.T) {
		t.Run("TestPolicyPass", testPolicyPass)
		t.Run("TestRulePass", testRulePass)
		t.Run("TestPolicyPassAllResourceTypes", testPolicyPassAllResourceTypes)
		t.Run("TestRulePassAllLogTypes", testRulePassAllLogTypes)
		t.Run("TestPolicyFail", testPolicyFail)
		t.Run("TestRuleFail", testRuleFail)
		t.Run("TestPolicyError", testPolicyError)
		t.Run("TestPolicyMixed", testPolicyMixed)
	})

	// These tests must be run before any data is input
	// TODO - maybe just move this to the delete test
	t.Run("TestEmpty", func(t *testing.T) {
		t.Run("ListDataModelsEmpty", testListDataModelsEmpty)
		t.Run("ListGlobalsEmpty", testListGlobalsEmpty)
		t.Run("ListPoliciesEmpty", testListPoliciesEmpty)
		t.Run("ListRulesEmpty", testListRulesEmpty)
	})

	t.Run("Create", func(t *testing.T) {
		t.Run("CreatePolicyInvalid", createInvalid)
		t.Run("CreatePolicySuccess", createPolicySuccess)
		t.Run("CreateRuleSuccess", createRuleSuccess)
		// This test (and the other global tests) does trigger the layer-manager lambda to run, but since there is only
		// support for a single global nothing changes (the version gets bumped a few times). Once multiple globals are
		// supported, these tests can be improved to run policies and rules that rely on these imports.
		t.Run("CreateGlobalSuccess", createGlobalSuccess)
		t.Run("CreateDataModel", createDataModel)

		t.Run("SaveEnabledPolicyFailingTests", saveEnabledPolicyFailingTests)
		t.Run("SaveDisabledPolicyFailingTests", saveDisabledPolicyFailingTests)
		t.Run("SaveEnabledPolicyPassingTests", saveEnabledPolicyPassingTests)
		t.Run("SavePolicyInvalidTestInputJson", savePolicyInvalidTestInputJSON)

		t.Run("SaveEnabledRuleFailingTests", saveEnabledRuleFailingTests)
		t.Run("SaveDisabledRuleFailingTests", saveDisabledRuleFailingTests)
		t.Run("SaveEnabledRulePassingTests", saveEnabledRulePassingTests)
		t.Run("SaveRuleInvalidTestInputJson", saveRuleInvalidTestInputJSON)
	})
	if t.Failed() {
		return
	}

	t.Run("Get", func(t *testing.T) {
		t.Run("GetNotFound", getNotFound)
		t.Run("GetLatest", getLatest)
		t.Run("GetVersion", getVersion)
		t.Run("GetRule", getRule)
		t.Run("GetRuleWrongType", getRuleWrongType)
		t.Run("GetGlobal", getGlobal)
		t.Run("GetDataModel", getDataModel)
	})

	// NOTE! This will mutate the original policy above!
	t.Run("BulkUpload", func(t *testing.T) {
		t.Run("BulkUploadInvalid", bulkUploadInvalid)
		t.Run("BulkUploadSuccess", bulkUploadSuccess)
	})
	if t.Failed() {
		return
	}

	t.Run("List", func(t *testing.T) {
		t.Run("ListPolicies", listPolicies)
		t.Run("ListFiltered", listFiltered)
		t.Run("ListPaging", listPaging)
		t.Run("ListProjection", listProjection)
		t.Run("ListRules", listRules)
		t.Run("ListGlobals", listGlobals)
		t.Run("ListDataModels", listDataModels)
	})

	t.Run("Modify", func(t *testing.T) {
		t.Run("ModifyNotFound", modifyNotFound)
		t.Run("ModifySuccess", modifySuccess)
		t.Run("ModifyRule", modifyRule)
		t.Run("ModifyGlobal", modifyGlobal)
		t.Run("ModifyDataModel", modifyDataModel)
	})
	//
	//	t.Run("Suppress", func(t *testing.T) {
	//		t.Run("SuppressNotFound", suppressNotFound)
	//		t.Run("SuppressSuccess", suppressSuccess)
	//	})
	//
	//	t.Run("Delete", func(t *testing.T) {
	//		t.Run("DeleteInvalid", deleteInvalid)
	//		t.Run("DeleteNotExists", deleteNotExists)
	//		t.Run("DeleteSuccess", deleteSuccess)
	//		t.Run("DeleteDataModel", deleteDataModel)
	//		t.Run("DeleteGlobal", deleteGlobal)
	//	})
	//}
}

func testPolicyPass(t *testing.T) {
	t.Parallel()
	testPolicy := models.LambdaInput{
		TestPolicy: &models.TestPolicyInput{
			Body:          policy.Body,
			ResourceTypes: []string{"AWS.S3.Bucket"},
			Tests:         policy.Tests,
		},
	}
	expected := models.TestPolicyOutput{
		TestSummary:  true,
		TestsErrored: []models.TestError{},
		TestsFailed:  []string{},
		TestsPassed:  []string{policy.Tests[0].Name, policy.Tests[1].Name},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&testPolicy, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testRulePass(t *testing.T) {
	t.Parallel()
	testRule := models.LambdaInput{
		TestRule: &models.TestRuleInput{
			Body:     "def rule(e): return True",
			LogTypes: []string{"Osquery.Differential"},
			Tests: []models.UnitTest{
				{
					Name:           "This will be True",
					ExpectedResult: true,
					Resource:       `{}`,
				},
				{
					Name:           "This will also be True",
					ExpectedResult: true,
					Resource:       `{"nested": {}}`,
				},
			},
		},
	}
	expected := models.TestRuleOutput{
		TestSummary: true,
		Results: []models.RuleTestResult{
			{
				DedupOutput: "defaultDedupString:RuleAPITestRule",
				Passed:      true,
				Errored:     false,
				ID:          "0",
				RuleOutput:  true,
				RuleID:      "RuleAPITestRule",
				TestName:    policy.Tests[0].Name,
			}, {
				DedupOutput: "defaultDedupString:RuleAPITestRule",
				Passed:      true,
				Errored:     false,
				ID:          "1",
				RuleOutput:  true,
				RuleID:      "RuleAPITestRule",
				TestName:    policy.Tests[1].Name,
			},
		},
	}

	var result models.TestRuleOutput
	statusCode, err := apiClient.Invoke(&testRule, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testPolicyPassAllResourceTypes(t *testing.T) {
	t.Parallel()
	testPolicy := models.LambdaInput{
		TestPolicy: &models.TestPolicyInput{
			Body:          "def policy(resource): return True",
			ResourceTypes: []string{},   // means applicable to all resource types
			Tests:         policy.Tests, // just reuse from the example policy
		},
	}
	expected := models.TestPolicyOutput{
		TestSummary:  true,
		TestsErrored: []models.TestError{},
		TestsFailed:  []string{},
		TestsPassed:  []string{policy.Tests[0].Name, policy.Tests[1].Name},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&testPolicy, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testRulePassAllLogTypes(t *testing.T) {
	t.Parallel()
	testRule := models.LambdaInput{
		TestRule: &models.TestRuleInput{
			Body:     "def rule(e): return True",
			LogTypes: []string{}, // means applicable to all log types
			Tests: []models.UnitTest{
				{
					Name:           "This will be True",
					ExpectedResult: true,
					Resource:       `{}`,
				},
			},
		},
	}
	expected := models.TestRuleOutput{
		TestSummary: true,
		Results: []models.RuleTestResult{
			{
				DedupOutput: "defaultDedupString:RuleAPITestRule",
				Passed:      true,
				Errored:     false,
				ID:          "0",
				RuleOutput:  true,
				RuleID:      "RuleAPITestRule",
				TestName:    policy.Tests[0].Name,
			},
		},
	}

	var result models.TestRuleOutput
	statusCode, err := apiClient.Invoke(&testRule, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testPolicyFail(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		TestPolicy: &models.TestPolicyInput{
			Body:          "def policy(resource): return False",
			ResourceTypes: policy.ResourceTypes,
			Tests:         policy.Tests,
		},
	}
	expected := models.TestPolicyOutput{
		TestSummary:  false,
		TestsErrored: []models.TestError{},
		TestsFailed:  []string{policy.Tests[0].Name, policy.Tests[1].Name},
		TestsPassed:  []string{},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testRuleFail(t *testing.T) {
	t.Parallel()
	testRule := models.LambdaInput{
		TestRule: &models.TestRuleInput{
			Body:     "def rule(e): return False",
			LogTypes: policy.ResourceTypes,
			Tests: []models.UnitTest{
				{
					Name:           "This will be True",
					ExpectedResult: true,
					Resource:       `{}`,
				},
			},
		},
	}
	expected := models.TestRuleOutput{
		TestSummary: false,
		Results: []models.RuleTestResult{
			{
				DedupOutput: "defaultDedupString:RuleAPITestRule",
				Passed:      false,
				Errored:     false,
				ID:          "0",
				RuleOutput:  false,
				RuleID:      "RuleAPITestRule",
				TestName:    policy.Tests[0].Name,
			},
		},
	}

	var result models.TestRuleOutput
	statusCode, err := apiClient.Invoke(&testRule, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testPolicyError(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		TestPolicy: &models.TestPolicyInput{
			Body:          "whatever, I do what I want",
			ResourceTypes: policy.ResourceTypes,
			Tests:         policy.Tests,
		},
	}
	expected := models.TestPolicyOutput{
		TestSummary: false,
		TestsErrored: []models.TestError{
			{
				ErrorMessage: "SyntaxError: invalid syntax (PolicyApiTestingPolicy.py, line 1)",
				Name:         policy.Tests[0].Name,
			},
			{
				ErrorMessage: "SyntaxError: invalid syntax (PolicyApiTestingPolicy.py, line 1)",
				Name:         policy.Tests[1].Name,
			},
		},
		TestsFailed: []string{},
		TestsPassed: []string{},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testPolicyMixed(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		TestPolicy: &models.TestPolicyInput{
			Body:          "def policy(resource): return resource['Hello']",
			ResourceTypes: policy.ResourceTypes,
			Tests: []models.UnitTest{
				{
					ExpectedResult: true,
					Name:           "test-1",
					Resource:       `{"Hello": true}`,
				},
				{
					ExpectedResult: false,
					Name:           "test-2",
					Resource:       `{"Hello": false}`,
				},
				{
					ExpectedResult: true,
					Name:           "test-3",
					Resource:       `{"Hello": false}`,
				},
				{
					ExpectedResult: true,
					Name:           "test-4",
					Resource:       `{"Goodbye": false}`,
				},
			},
		},
	}
	expected := models.TestPolicyOutput{
		TestSummary: false,
		TestsErrored: []models.TestError{
			{
				ErrorMessage: "KeyError: 'Hello'",
				Name:         "test-4",
			},
		},
		TestsFailed: []string{"test-3"},
		TestsPassed: []string{"test-1", "test-2"},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testListDataModelsEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDataModels: &models.ListDataModelsInput{},
	}
	var result models.ListDataModelsOutput

	expected := models.ListDataModelsOutput{Models: []models.DataModel{}}
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testListGlobalsEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListGlobals: &models.ListGlobalsInput{},
	}
	var result models.ListGlobalsOutput

	expected := models.ListGlobalsOutput{Globals: []models.Global{}}
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testListPoliciesEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{},
	}
	var result models.ListPoliciesOutput

	expected := models.ListPoliciesOutput{Policies: []models.Policy{}}
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testListRulesEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListRules: &models.ListRulesInput{},
	}
	var result models.ListRulesOutput

	expected := models.ListRulesOutput{Rules: []models.Rule{}}
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func createInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		CreatePolicy: &models.CreatePolicyInput{},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	assert.Equal(t, http.StatusBadRequest, statusCode)
	assert.Error(t, err)
}

func createPolicySuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		CreatePolicy: &models.CreatePolicyInput{
			CoreEntryUpdate: models.CoreEntryUpdate{
				Body:        policy.Body,
				Description: policy.Description,
				ID:          policy.ID,
				Tags:        policy.Tags,
				UserID:      userID,
			},
			PythonDetection: models.PythonDetection{
				DisplayName: policy.DisplayName,
				Enabled:     policy.Enabled,
				Severity:    policy.Severity,
				OutputIDs:   policy.OutputIDs,
				Tests:       policy.Tests,
			},
			AutoRemediationID:         policy.AutoRemediationID,
			AutoRemediationParameters: policy.AutoRemediationParameters,
			ResourceTypes:             policy.ResourceTypes,
			Suppressions:              policy.Suppressions,
		},
	}
	var result models.Policy
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, statusCode)

	assert.NotEmpty(t, result.ComplianceStatus)
	assert.NotZero(t, result.CreatedAt)
	assert.NotZero(t, result.LastModified)

	expectedPolicy := *policy
	expectedPolicy.ComplianceStatus = result.ComplianceStatus
	expectedPolicy.CreatedAt = result.CreatedAt
	expectedPolicy.CreatedBy = userID
	expectedPolicy.LastModified = result.LastModified
	expectedPolicy.LastModifiedBy = userID
	expectedPolicy.VersionID = result.VersionID
	assert.Equal(t, expectedPolicy, result)
	policy = &result
}

// Tests that a policy cannot be saved if it is enabled and its tests fail.
func saveEnabledPolicyFailingTests(t *testing.T) {
	t.Parallel()
	policyID := uuid.New().String()
	defer cleanupAnalyses(t, policyID)

	req := models.UpdatePolicyInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def policy(resource): return resource['key']",
			ID:     policyID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  true,
			Severity: policy.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "This will pass",
					ExpectedResult: true,
					Resource:       `{"key":true}`,
				}, {
					Name:           "This will fail",
					ExpectedResult: false,
					Resource:       `{"key":true}`,
				}, {
					Name:           "This will fail too",
					ExpectedResult: false,
					Resource:       `{}`,
				},
			},
		},
	}

	expectedErrorMessage := "cannot save an enabled policy with failing unit tests"
	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})
}

// Tests a disabled policy can be saved even if its tests fail.
func saveDisabledPolicyFailingTests(t *testing.T) {
	t.Parallel()
	policyID := uuid.New().String()
	defer cleanupAnalyses(t, policyID)

	req := models.UpdatePolicyInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def policy(resource): return True",
			ID:     policyID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  false,
			Severity: policy.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "This will fail",
					ExpectedResult: false,
					Resource:       `{}`,
				},
			},
		},
	}

	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, statusCode)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
	})
}

// Tests that a policy can be saved if it is enabled and its tests pass.
func saveEnabledPolicyPassingTests(t *testing.T) {
	t.Parallel()
	policyID := uuid.New().String()
	defer cleanupAnalyses(t, policyID)

	req := models.UpdatePolicyInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def policy(resource): return True",
			ID:     policyID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  true,
			Severity: policy.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "Compliant",
					ExpectedResult: true,
					Resource:       `{}`,
				}, {
					Name:           "Compliant 2",
					ExpectedResult: true,
					Resource:       `{}`,
				},
			},
		},
	}

	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, statusCode)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
	})
}

func savePolicyInvalidTestInputJSON(t *testing.T) {
	t.Parallel()
	policyID := uuid.New().String()
	defer cleanupAnalyses(t, policyID)

	req := models.UpdatePolicyInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def policy(resource): return True",
			ID:     policyID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  true,
			Severity: policy.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "PolicyName",
					ExpectedResult: true,
					Resource:       "invalid json",
				},
			},
		},
	}

	expectedErrorMessage := fmt.Sprintf(`Resource for test "%s" is not valid json:`, req.Tests[0].Name)
	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdatePolicy: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})
}

// Tests that a rule cannot be saved if it is enabled and its tests fail.
func saveEnabledRuleFailingTests(t *testing.T) {
	t.Parallel()
	ruleID := uuid.New().String()
	defer cleanupAnalyses(t, ruleID)

	req := models.UpdateRuleInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def rule(event): return event['key']",
			ID:     ruleID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  true,
			Severity: rule.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "This will fail",
					ExpectedResult: false,
					Resource:       `{"key":true}`,
				}, {
					Name:           "This will fail too",
					ExpectedResult: true,
					Resource:       `{}`,
				}, {
					Name:           "This will pass",
					ExpectedResult: true,
					Resource:       `{"key":true}`,
				},
			},
		},
	}

	expectedErrorMessage := "cannot save an enabled rule with failing unit tests"
	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})
}

// Tests that a rule can be saved if it is enabled and its tests pass.
// This is different than createRuleSuccess test. createRuleSuccess saves
// a rule without tests.
func saveEnabledRulePassingTests(t *testing.T) {
	t.Parallel()
	ruleID := uuid.New().String()
	defer cleanupAnalyses(t, ruleID)

	req := models.UpdateRuleInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def rule(event): return True",
			ID:     ruleID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  true,
			Severity: rule.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "Trigger alert",
					ExpectedResult: true,
					Resource:       `{}`,
				}, {
					Name:           "Trigger alert 2",
					ExpectedResult: true,
					Resource:       `{}`,
				},
			},
		},
	}

	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, statusCode)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
	})
}

func saveRuleInvalidTestInputJSON(t *testing.T) {
	t.Parallel()
	ruleID := uuid.New().String()
	defer cleanupAnalyses(t, ruleID)

	req := models.UpdateRuleInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def rule(event): return True",
			ID:     ruleID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  true,
			Severity: rule.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "Trigger alert",
					ExpectedResult: true,
					Resource:       "invalid json",
				},
			},
		},
	}

	expectedErrorMessage := fmt.Sprintf(`Event for test "%s" is not valid json:`, req.Tests[0].Name)
	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, statusCode)
		assert.Contains(t, err.Error(), expectedErrorMessage)
	})
}

// Tests a disabled policy can be saved even if its tests fail.
func saveDisabledRuleFailingTests(t *testing.T) {
	t.Parallel()
	ruleID := uuid.New().String()
	defer cleanupAnalyses(t, ruleID)

	req := models.UpdateRuleInput{
		CoreEntryUpdate: models.CoreEntryUpdate{
			Body:   "def rule(event): return True",
			ID:     ruleID,
			UserID: userID,
		},
		PythonDetection: models.PythonDetection{
			Enabled:  false,
			Severity: rule.Severity,
			Tests: []models.UnitTest{
				{
					Name:           "This will fail",
					ExpectedResult: false,
					Resource:       `{}`,
				},
			},
		},
	}

	t.Run("Create", func(t *testing.T) {
		input := models.LambdaInput{CreateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, statusCode)
	})

	t.Run("Modify", func(t *testing.T) {
		input := models.LambdaInput{UpdateRule: &req}
		statusCode, err := apiClient.Invoke(&input, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
	})
}

func createRuleSuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		CreateRule: &models.CreateRuleInput{
			CoreEntryUpdate: models.CoreEntryUpdate{
				Body:        rule.Body,
				Description: rule.Description,
				ID:          rule.ID,
				Tags:        rule.Tags,
				UserID:      userID,
			},
			PythonDetection: models.PythonDetection{
				Enabled:   rule.Enabled,
				Severity:  rule.Severity,
				OutputIDs: rule.OutputIDs,
			},
			DedupPeriodMinutes: rule.DedupPeriodMinutes,
			LogTypes:           rule.LogTypes,
			Threshold:          rule.Threshold,
		},
	}
	var result models.Rule
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, statusCode)

	assert.NotZero(t, result.CreatedAt)
	assert.NotZero(t, result.LastModified)

	expectedRule := *rule
	expectedRule.CreatedAt = result.CreatedAt
	expectedRule.CreatedBy = userID
	expectedRule.LastModified = result.LastModified
	expectedRule.LastModifiedBy = userID
	expectedRule.VersionID = result.VersionID
	assert.Equal(t, expectedRule, result)
	rule = &result
}

func createDataModel(t *testing.T) {
	t.Parallel()

	for _, model := range dataModels {
		input := models.LambdaInput{
			CreateDataModel: &models.CreateDataModelInput{
				Body:        model.Body,
				Description: model.Description,
				Enabled:     model.Enabled,
				ID:          model.ID,
				LogTypes:    model.LogTypes,
				Mappings:    model.Mappings,
				UserID:      userID,
			},
		}
		var result models.DataModel
		statusCode, err := apiClient.Invoke(&input, &result)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, statusCode)

		assert.NotZero(t, result.CreatedAt)
		assert.NotZero(t, result.LastModified)

		model.CreatedAt = result.CreatedAt
		model.CreatedBy = userID
		model.LastModified = result.LastModified
		model.LastModifiedBy = userID
		model.VersionID = result.VersionID
		assert.Equal(t, *model, result)
	}

	// This should fail because it tries to create a DataModel
	// for a logType that already has a DataModel enabled
	input := models.LambdaInput{
		CreateDataModel: &models.CreateDataModelInput{
			Body:        "def get_source_ip(event): return 'source_ip'\n",
			Description: "Example LogType Schema",
			Enabled:     true,
			ID:          "AnotherDataModelTypeAnalysis",
			LogTypes:    []string{"OneLogin.Events"},
			Mappings:    []models.DataModelMapping{},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)

	// This should fail because it attempts to add a mapping with both a field and a method
	input = models.LambdaInput{
		CreateDataModel: &models.CreateDataModelInput{
			Body:        "def get_source_ip(event): return 'source_ip'\n",
			Description: "Example LogType Schema",
			Enabled:     true,
			ID:          "AnotherDataModelTypeAnalysis",
			LogTypes:    []string{"Unique.Events"},
			Mappings: []models.DataModelMapping{
				{
					Name:   "source_ip",
					Path:   "src_ip",
					Method: "get_source_ip",
				},
			},
		},
	}
	statusCode, err = apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)
}

func createGlobalSuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		CreateGlobal: &models.CreateGlobalInput{
			CoreEntryUpdate: models.CoreEntryUpdate{
				Body:        global.Body,
				Description: global.Description,
				ID:          global.ID,
				UserID:      userID,
			},
		},
	}
	var result models.Global
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, statusCode)

	assert.NotZero(t, result.CreatedAt)
	assert.NotZero(t, result.LastModified)

	global.CreatedAt = result.CreatedAt
	global.CreatedBy = userID
	global.LastModified = result.LastModified
	global.LastModifiedBy = userID
	global.Tags = []string{} // nil was converted to empty list
	global.VersionID = result.VersionID
	assert.Equal(t, *global, result)
}

func getNotFound(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetPolicy: &models.GetPolicyInput{PolicyID: "does-not-exist"},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

// Get the latest policy version (from Dynamo)
func getLatest(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetPolicy: &models.GetPolicyInput{PolicyID: policy.ID},
	}
	var result models.Policy
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, *policy, result)
}

// Get a specific policy version (from S3)
func getVersion(t *testing.T) {
	t.Parallel()

	// first get the version now as latest
	input := models.LambdaInput{
		GetPolicy: &models.GetPolicyInput{PolicyID: policy.ID},
	}
	var result models.Policy
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	versionedPolicy = &result // remember for later in delete tests, since it will change

	// now look it up
	input.GetPolicy.VersionID = result.VersionID
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, *policy, result)
}

func getRule(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetRule: &models.GetRuleInput{RuleID: rule.ID},
	}
	var result models.Rule
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, *rule, result)
}

func getDataModel(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetDataModel: &models.GetDataModelInput{DataModelID: dataModel.ID},
	}
	var result models.DataModel
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, *dataModel, result)
}

func getGlobal(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetGlobal: &models.GetGlobalInput{GlobalID: global.ID},
	}
	var result models.Global
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, *global, result)
}

// GetRule with a policy ID returns 404 not found
func getRuleWrongType(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetRule: &models.GetRuleInput{RuleID: policy.ID},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

func modifyNotFound(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		UpdatePolicy: &models.UpdatePolicyInput{
			CoreEntryUpdate: models.CoreEntryUpdate{
				Body:   "def policy(resource): return False",
				ID:     "DOES.NOT.EXIST",
				UserID: userID,
			},
			PythonDetection: models.PythonDetection{
				Enabled:  policy.Enabled,
				Severity: policy.Severity,
			},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

func modifySuccess(t *testing.T) {
	t.Parallel()
	// things we will change
	expectedPolicy := *policy
	expectedPolicy.Description = "A new and modified description!"
	expectedPolicy.Tests = []models.UnitTest{
		{
			Name:           "This will be True",
			ExpectedResult: true,
			Resource:       `{}`,
		},
	}
	input := models.LambdaInput{
		UpdatePolicy: &models.UpdatePolicyInput{
			CoreEntryUpdate: models.CoreEntryUpdate{
				Body:        policy.Body,
				Description: expectedPolicy.Description,
				ID:          policy.ID,
				Tags:        policy.Tags,
				UserID:      userID,
			},
			PythonDetection: models.PythonDetection{
				DisplayName: policy.DisplayName,
				Enabled:     policy.Enabled,
				OutputIDs:   policy.OutputIDs,
				Reference:   policy.Reference,
				Reports:     policy.Reports,
				Runbook:     policy.Runbook,
				Severity:    policy.Severity,
				Tests:       expectedPolicy.Tests,
			},
			AutoRemediationID:         policy.AutoRemediationID,
			AutoRemediationParameters: policy.AutoRemediationParameters,
			ResourceTypes:             policy.ResourceTypes,
			Suppressions:              policy.Suppressions,
		},
	}
	var result models.Policy
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// these get assigned
	assert.NotEmpty(t, result.LastModified)
	assert.NotEmpty(t, result.VersionID)
	expectedPolicy.LastModified = result.LastModified
	expectedPolicy.VersionID = result.VersionID
	assert.Equal(t, expectedPolicy, result)
}

// Modify a rule
func modifyRule(t *testing.T) {
	t.Parallel()
	// these are changes
	expectedRule := *rule
	expectedRule.Description = "SkyNet integration"
	expectedRule.DedupPeriodMinutes = 60
	expectedRule.Threshold = rule.Threshold + 1

	input := models.LambdaInput{
		UpdateRule: &models.UpdateRuleInput{
			CoreEntryUpdate: models.CoreEntryUpdate{
				Body:        rule.Body,
				Description: expectedRule.Description,
				ID:          rule.ID,
				Tags:        rule.Tags,
				UserID:      userID,
			},
			PythonDetection: rule.PythonDetection,

			DedupPeriodMinutes: expectedRule.DedupPeriodMinutes,
			LogTypes:           rule.LogTypes,
			Threshold:          expectedRule.Threshold,
		},
	}
	var result models.Rule
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	assert.NotEmpty(t, result.LastModified)
	assert.NotEmpty(t, result.VersionID)

	expectedRule.LastModified = result.LastModified
	expectedRule.VersionID = result.VersionID
	assert.Equal(t, expectedRule, result)
}

func modifyDataModel(t *testing.T) {
	t.Parallel()
	dataModel.Description = "A new description"
	dataModel.Body = "def get_source_ip(event): return src_ip\n"

	input := models.LambdaInput{
		UpdateDataModel: &models.UpdateDataModelInput{
			Body:        dataModel.Body,
			Description: dataModel.Description,
			DisplayName: dataModel.DisplayName,
			Enabled:     dataModel.Enabled,
			ID:          dataModel.ID,
			LogTypes:    dataModel.LogTypes,
			Mappings:    dataModel.Mappings,
			UserID:      userID,
		},
	}
	var result models.DataModel
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	assert.NotEmpty(t, result.LastModified)
	assert.NotEmpty(t, result.VersionID)

	dataModel.LastModified = result.LastModified
	dataModel.VersionID = result.VersionID
	assert.Equal(t, *dataModel, result)

	// verify can update logtypes to overlap if enabled is false
	originalLogTypes := dataModel.LogTypes
	dataModel.Enabled = false
	dataModel.LogTypes = dataModelTwo.LogTypes

	input.UpdateDataModel.Enabled = dataModel.Enabled
	input.UpdateDataModel.LogTypes = dataModel.LogTypes
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	dataModel.LastModified = result.LastModified
	dataModel.VersionID = result.VersionID
	assert.Equal(t, *dataModel, result)

	// change logtype back
	dataModel.Enabled = true
	dataModel.LogTypes = originalLogTypes
	input.UpdateDataModel.Enabled = dataModel.Enabled
	input.UpdateDataModel.LogTypes = dataModel.LogTypes
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	dataModel.LastModified = result.LastModified
	dataModel.VersionID = result.VersionID
	assert.Equal(t, *dataModel, result)

	// Updating the logtypes that would create two data models
	// that cover the same logtypes fails
	input.UpdateDataModel.LogTypes = dataModelTwo.LogTypes
	statusCode, err = apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)
}

// Modify a global
func modifyGlobal(t *testing.T) {
	t.Parallel()
	global.Description = "Now returns False"
	global.Body = "def helper_is_true(truthy): return truthy is False\n"

	input := models.LambdaInput{
		UpdateGlobal: &models.UpdateGlobalInput{
			CoreEntryUpdate: models.CoreEntryUpdate{
				Body:        global.Body,
				Description: global.Description,
				ID:          global.ID,
				Tags:        global.Tags,
				UserID:      userID,
			},
		},
	}
	var result models.Global
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	assert.NotEmpty(t, result.LastModified)
	assert.NotEmpty(t, result.VersionID)

	global.LastModified = result.LastModified
	global.VersionID = result.VersionID
	assert.Equal(t, *global, result)
}

//func suppressNotFound(t *testing.T) {
//	result, err := apiClient.Operations.Suppress(&operations.SuppressParams{
//		Body: &models.Suppress{
//			PolicyIds:        []models.ID{"no-such-id"},
//			ResourcePatterns: models.Suppressions{"s3:.*"},
//		},
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	// a policy which doesn't exist logs a warning but doesn't return an API error
//	assert.Equal(t, &operations.SuppressOK{}, result)
//}
//
//func suppressSuccess(t *testing.T) {
//	result, err := apiClient.Operations.Suppress(&operations.SuppressParams{
//		Body: &models.Suppress{
//			PolicyIds:        []models.ID{policy.ID},
//			ResourcePatterns: models.Suppressions{"new-suppression"},
//		},
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	assert.Equal(t, &operations.SuppressOK{}, result)
//
//	// Verify suppressions were added correctly
//	getResult, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
//		PolicyID:   string(policy.ID),
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	sort.Strings(getResult.Payload.Suppressions)
//	// It was added to the existing suppressions
//	assert.Equal(t, models.Suppressions{"new-suppression", "panther.*"}, getResult.Payload.Suppressions)
//}

func bulkUploadInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		BulkUpload: &models.BulkUploadInput{},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)
}

func bulkUploadSuccess(t *testing.T) {
	t.Parallel()
	require.NoError(t, shutil.ZipDirectory(analysesRoot, analysesZipLocation, true))
	zipFile, err := os.Open(analysesZipLocation)
	require.NoError(t, err)
	content, err := ioutil.ReadAll(bufio.NewReader(zipFile))
	require.NoError(t, err)

	// cleaning up added Rule
	defer cleanupAnalyses(t, "Rule.Always.True")

	encoded := base64.StdEncoding.EncodeToString(content)
	input := models.LambdaInput{
		BulkUpload: &models.BulkUploadInput{Data: encoded, UserID: userID},
	}
	var result models.BulkUploadOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.BulkUploadOutput{
		ModifiedPolicies: 1,
		NewPolicies:      2,
		TotalPolicies:    3,

		ModifiedRules: 0,
		NewRules:      1,
		TotalRules:    1,

		ModifiedGlobals: 0,
		NewGlobals:      0,
		TotalGlobals:    0,

		ModifiedDataModels: 0,
		NewDataModels:      1,
		TotalDataModels:    1,
	}
	require.Equal(t, expected, result)

	// Verify the existing policy was updated - the created fields were unchanged
	input = models.LambdaInput{
		GetPolicy: &models.GetPolicyInput{PolicyID: policy.ID},
	}
	var getResult models.Policy
	_, err = apiClient.Invoke(&input, &getResult)
	require.NoError(t, err)

	assert.True(t, getResult.LastModified.After(policy.LastModified))
	assert.NotEqual(t, getResult.VersionID, policy.VersionID)
	assert.NotEmpty(t, getResult.VersionID)

	expectedPolicy := *policy
	expectedPolicy.AutoRemediationID = "fix-it"
	expectedPolicy.AutoRemediationParameters = map[string]string{"hello": "goodbye"}
	expectedPolicy.CreatedAt = getResult.CreatedAt
	expectedPolicy.CreatedBy = getResult.CreatedBy
	expectedPolicy.Description = "Matches every resource\n"
	expectedPolicy.LastModifiedBy = getResult.LastModifiedBy
	expectedPolicy.LastModified = getResult.LastModified
	expectedPolicy.OutputIDs = []string{}
	expectedPolicy.ResourceTypes = []string{"AWS.S3.Bucket"}
	expectedPolicy.Suppressions = []string{"panther.*"}
	expectedPolicy.Tags = []string{}
	expectedPolicy.Tests = expectedPolicy.Tests[:1]
	expectedPolicy.Tests[0].Resource = `{"Bucket":"empty"}`
	expectedPolicy.VersionID = getResult.VersionID
	assert.Equal(t, expectedPolicy, getResult)

	// Now reset global policy so subsequent tests have a reference
	policy = &getResult

	// Verify newly created policy #1
	input.GetPolicy.PolicyID = policyFromBulk.ID
	_, err = apiClient.Invoke(&input, &policyFromBulk)
	require.NoError(t, err)

	assert.NotZero(t, policyFromBulk.CreatedAt)
	assert.NotZero(t, policyFromBulk.LastModified)

	cloudtrailBody, err := ioutil.ReadFile(path.Join(analysesRoot, "policy_aws_cloudtrail_log_validation_enabled.py"))
	require.NoError(t, err)
	assert.Equal(t, policyFromBulk.Body, string(cloudtrailBody))
	assert.Len(t, policyFromBulk.Tests, 2)

	// Verify newly created policy #2
	input.GetPolicy.PolicyID = policyFromBulkJSON.ID
	_, err = apiClient.Invoke(&input, &policyFromBulkJSON)
	require.NoError(t, err)
	assert.Equal(t, "Matches every resource", policyFromBulkJSON.Description)
	assert.Equal(t, "Test:Policy:JSON", policyFromBulkJSON.ID)

	// Verify newly created Rule
	expectedNewRule := models.Rule{
		CoreEntry: models.CoreEntry{
			Body:           "",
			CreatedAt:      time.Time{},
			CreatedBy:      "",
			Description:    "Test rule",
			ID:             "Rule.Always.True",
			LastModified:   time.Time{},
			LastModifiedBy: "",
			Tags:           []string{"DNS"},
			VersionID:      "",
		},
		PythonDetection: models.PythonDetection{
			DisplayName: "Rule Always True display name",
			Enabled:     true,
			OutputIDs:   []string{},
			Reference:   "",
			Reports:     map[string][]string{},
			Runbook:     "Test runbook",
			Severity:    compliancemodels.SeverityLow,
			Tests:       []models.UnitTest{},
		},
		DedupPeriodMinutes: 480,
		LogTypes:           []string{"CiscoUmbrella.DNS"},
		Threshold:          42,
	}

	input = models.LambdaInput{
		GetRule: &models.GetRuleInput{RuleID: expectedNewRule.ID},
	}
	var getRule models.Rule
	_, err = apiClient.Invoke(&input, &getRule)
	require.NoError(t, err)

	// Setting the below to the value received
	// since we have no control over them
	expectedNewRule.CreatedAt = getRule.CreatedAt
	expectedNewRule.CreatedBy = getRule.CreatedBy
	expectedNewRule.LastModified = getRule.LastModified
	expectedNewRule.LastModifiedBy = getRule.LastModifiedBy
	expectedNewRule.VersionID = getRule.VersionID
	expectedNewRule.Body = getRule.Body
	assert.Equal(t, expectedNewRule, getRule)
	// Checking if the body contains the provide `rule` function (the body contains licence information that we are not interested in)
	assert.Contains(t, getRule.Body, "def rule(event):\n    return True\n")

	// Verify newly created DataModel
	input = models.LambdaInput{
		GetDataModel: &models.GetDataModelInput{DataModelID: dataModelFromBulkYML.ID},
	}
	var getDataModel models.DataModel
	_, err = apiClient.Invoke(&input, &getDataModel)
	require.NoError(t, err)

	// setting updated values
	dataModelFromBulkYML.CreatedAt = getDataModel.CreatedAt
	dataModelFromBulkYML.CreatedBy = getDataModel.CreatedBy
	dataModelFromBulkYML.LastModified = getDataModel.LastModified
	dataModelFromBulkYML.LastModifiedBy = getDataModel.LastModifiedBy
	dataModelFromBulkYML.VersionID = getDataModel.VersionID
	assert.Equal(t, *dataModelFromBulkYML, getDataModel)
}

func listPolicies(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{},
	}
	var result models.ListPoliciesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListPoliciesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 1,
		},
		Policies: []models.Policy{ // sorted by id
			*policyFromBulk,     // AWS.CloudTrail.Log.Validation.Enabled
			*policy,             // Test:Policy
			*policyFromBulkJSON, // Test:Policy:JSON
		},
	}
	assert.Equal(t, expected, result)
}

func listFiltered(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{
			Enabled:        aws.Bool(true),
			HasRemediation: aws.Bool(true),
			NameContains:   "json", // policyFromBulkJSON only
			ResourceTypes:  []string{"AWS.S3.Bucket"},
			Severity:       compliancemodels.SeverityMedium,
		},
	}
	var result models.ListPoliciesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListPoliciesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 1,
			TotalPages: 1,
		},
		Policies: []models.Policy{*policyFromBulkJSON},
	}
	assert.Equal(t, expected, result)
}

func listPaging(t *testing.T) {
	t.Parallel()
	// Page 1
	input := models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{
			PageSize: 1,
			SortBy:   "id",
			SortDir:  "descending",
		},
	}
	var result models.ListPoliciesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListPoliciesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 3,
		},
		Policies: []models.Policy{*policyFromBulkJSON},
	}
	assert.Equal(t, expected, result)

	// Page 2
	input.ListPolicies.Page = 2
	result = models.ListPoliciesOutput{}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected = models.ListPoliciesOutput{
		Paging: models.Paging{
			ThisPage:   2,
			TotalItems: 3,
			TotalPages: 3,
		},
		Policies: []models.Policy{*policy},
	}
	assert.Equal(t, expected, result)

	// Page 3
	input.ListPolicies.Page = 3
	result = models.ListPoliciesOutput{}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected = models.ListPoliciesOutput{
		Paging: models.Paging{
			ThisPage:   3,
			TotalItems: 3,
			TotalPages: 3,
		},
		Policies: []models.Policy{*policyFromBulk},
	}
	assert.Equal(t, expected, result)
}

func listProjection(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{
			// Select only a subset of fields
			Fields: []string{"id", "displayName"},
		},
	}
	var result models.ListPoliciesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Empty lists/maps will always be initialized in the response
	emptyPolicy := models.Policy{
		CoreEntry: models.CoreEntry{
			Tags: []string{},
		},
		PythonDetection: models.PythonDetection{
			OutputIDs: []string{},
			Reports:   map[string][]string{},
			Tests:     []models.UnitTest{},
		},
		AutoRemediationParameters: map[string]string{},
		ResourceTypes:             []string{},
		Suppressions:              []string{},
	}

	firstItem := emptyPolicy
	firstItem.ID = policyFromBulk.ID
	firstItem.DisplayName = policyFromBulk.DisplayName

	secondItem := emptyPolicy
	secondItem.ID = policy.ID
	secondItem.DisplayName = policy.DisplayName

	thirdItem := emptyPolicy
	thirdItem.ID = policyFromBulkJSON.ID
	thirdItem.DisplayName = policyFromBulkJSON.DisplayName

	expected := models.ListPoliciesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 1,
		},
		Policies: []models.Policy{firstItem, secondItem, thirdItem},
	}
	assert.Equal(t, expected, result)
}

func listRules(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListRules: &models.ListRulesInput{},
	}
	var result models.ListRulesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListRulesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 1,
			TotalPages: 1,
		},
		Rules: []models.Rule{*rule},
	}
	assert.Equal(t, expected, result)
}

func listGlobals(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListGlobals: &models.ListGlobalsInput{},
	}
	var result models.ListGlobalsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListGlobalsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 1,
			TotalPages: 1,
		},
		Globals: []models.Global{*global},
	}
	assert.Equal(t, expected, result)
}

func listDataModels(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDataModels: &models.ListDataModelsInput{},
	}
	var result models.ListDataModelsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListDataModelsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 1,
		},
		Models: []models.DataModel{
			*dataModel, *dataModelTwo, *dataModelFromBulkYML,
		},
	}
	assert.Equal(t, expected, result)
}

//
//func deleteInvalid(t *testing.T) {
//	result, err := apiClient.Operations.DeletePolicies(&operations.DeletePoliciesParams{
//		Body:       &models.DeletePolicies{},
//		HTTPClient: httpClient,
//	})
//	assert.Nil(t, result)
//	require.Error(t, err)
//	require.IsType(t, &operations.DeletePoliciesBadRequest{}, err)
//}
//
//// Delete a set of policies that don't exist - returns OK
//func deleteNotExists(t *testing.T) {
//	result, err := apiClient.Operations.DeletePolicies(&operations.DeletePoliciesParams{
//		Body: &models.DeletePolicies{
//			Policies: []*models.DeleteEntry{
//				{
//					ID: "does-not-exist",
//				},
//				{
//					ID: "also-does-not-exist",
//				},
//			},
//		},
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	assert.Equal(t, &operations.DeletePoliciesOK{}, result)
//}
//
//func deleteSuccess(t *testing.T) {
//	result, err := apiClient.Operations.DeletePolicies(&operations.DeletePoliciesParams{
//		Body: &models.DeletePolicies{
//			Policies: []*models.DeleteEntry{
//				{
//					ID: policy.ID,
//				},
//				{
//					ID: policyFromBulk.ID,
//				},
//				{
//					ID: policyFromBulkJSON.ID,
//				},
//				{
//					ID: rule.ID,
//				},
//			},
//		},
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	assert.Equal(t, &operations.DeletePoliciesOK{}, result)
//
//	// Trying to retrieve the deleted policy should now return 404
//	_, err = apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
//		PolicyID:   string(policy.ID),
//		HTTPClient: httpClient,
//	})
//	require.Error(t, err)
//	require.IsType(t, &operations.GetPolicyNotFound{}, err)
//
//	// But retrieving an older version will still work...
//	getResult, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
//		PolicyID:   string(versionedPolicy.ID),
//		VersionID:  aws.String(string(versionedPolicy.VersionID)),
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//
//	assert.Equal(t, versionedPolicy, getResult.Payload)
//
//	// List operations should be empty
//	emptyPaging := &models.Paging{
//		ThisPage:   aws.Int64(0),
//		TotalItems: aws.Int64(0),
//		TotalPages: aws.Int64(0),
//	}
//
//	policyList, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	expectedPolicyList := &models.PolicyList{Paging: emptyPaging, Policies: []*models.PolicySummary{}}
//	assert.Equal(t, expectedPolicyList, policyList.Payload)
//
//	ruleList, err := apiClient.Operations.ListRules(&operations.ListRulesParams{
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	expectedRuleList := &models.RuleList{Paging: emptyPaging, Rules: []*models.RuleSummary{}}
//	assert.Equal(t, expectedRuleList, ruleList.Payload)
//}
//
//func deleteDataModel(t *testing.T) {
//	allDataModels := make([]*models.DataModel, len(dataModels))
//	for i, model := range dataModels {
//		allDataModels[i] = model
//	}
//	allDataModels = append(allDataModels, dataModelFromBulkYML)
//	for _, model := range allDataModels {
//		result, err := apiClient.Operations.DeletePolicies(&operations.DeletePoliciesParams{
//			Body: &models.DeletePolicies{
//				Policies: []*models.DeleteEntry{
//					{
//						ID: model.ID,
//					},
//				},
//			},
//			HTTPClient: httpClient,
//		})
//		require.NoError(t, err)
//		assert.Equal(t, &operations.DeletePoliciesOK{}, result)
//
//		// Trying to retrieve the deleted data model should now return 404
//		_, err = apiClient.Operations.GetDataModel(&operations.GetDataModelParams{
//			DataModelID: string(model.ID),
//			HTTPClient:  httpClient,
//		})
//		require.Error(t, err)
//		require.IsType(t, &operations.GetDataModelNotFound{}, err)
//
//		// But retrieving an older version will still work
//		getResult, err := apiClient.Operations.GetDataModel(&operations.GetDataModelParams{
//			DataModelID: string(model.ID),
//			VersionID:   aws.String(string(model.VersionID)),
//			HTTPClient:  httpClient,
//		})
//		require.NoError(t, err)
//		assert.Equal(t, model, getResult.Payload)
//	}
//}
//
//func deleteGlobal(t *testing.T) {
//	result, err := apiClient.Operations.DeleteGlobals(&operations.DeleteGlobalsParams{
//		Body: &models.DeletePolicies{
//			Policies: []*models.DeleteEntry{
//				{
//					ID: global.ID,
//				},
//			},
//		},
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	assert.Equal(t, &operations.DeleteGlobalsOK{}, result)
//
//	// Trying to retrieve the deleted policy should now return 404
//	_, err = apiClient.Operations.GetGlobal(&operations.GetGlobalParams{
//		GlobalID:   string(global.ID),
//		HTTPClient: httpClient,
//	})
//	require.Error(t, err)
//	require.IsType(t, &operations.GetGlobalNotFound{}, err)
//
//	// But retrieving an older version will still work
//	getResult, err := apiClient.Operations.GetGlobal(&operations.GetGlobalParams{
//		GlobalID:   string(global.ID),
//		VersionID:  aws.String(string(global.VersionID)),
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	assert.Equal(t, global, getResult.Payload)
//}
//
// Can be used for both policies and rules since they share the same api handler.
func cleanupAnalyses(t *testing.T, analysisID ...string) {
	input := models.LambdaInput{
		DeleteDetections: &models.DeleteDetectionsInput{
			Entries: make([]models.DeleteEntry, len(analysisID)),
		},
	}

	for i, pid := range analysisID {
		input.DeleteDetections.Entries[i].ID = pid
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
}
