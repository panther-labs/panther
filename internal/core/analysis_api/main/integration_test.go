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
	"sort"
	"strings"
	"testing"

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

	userID = "test-panther-user" // does NOT need to be a uuid4

	// NOTE: this gets changed by the bulk upload!
	policy = &models.Policy{
		AnalysisType:              models.TypePolicy,
		AutoRemediationParameters: map[string]string{},
		Description:               "Matches every resource",
		DisplayName:               "AlwaysTrue",
		Enabled:                   true,
		ID:                        "Test:Policy",
		OutputIDs:                 []string{"policyOutput"},
		Reports:                   map[string][]string{},
		ResourceTypes:             []string{},
		Severity:                  compliancemodels.SeverityMedium,
		Suppressions:              []string{},
		Tags:                      []string{"policyTag"},
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
	}
	versionedPolicy *models.Policy // this will get set when we modify policy for use in delete testing

	// Set during bulk upload
	policyFromBulk     = &models.Policy{ID: "AWS.CloudTrail.Log.Validation.Enabled"}
	policyFromBulkJSON = &models.Policy{ID: "Test:Policy:JSON"}

	rule = &models.Rule{
		AnalysisType:       models.TypeRule,
		Body:               "def rule(event): return len(event) > 0\n",
		DedupPeriodMinutes: 1440,
		Description:        "Matches every non-empty event",
		Enabled:            true,
		ID:                 "NonEmptyEvent",
		LogTypes:           []string{"AWS.CloudTrail"},
		OutputIDs:          []string{"test-output1", "test-output2"},
		Reports:            map[string][]string{},
		Severity:           compliancemodels.SeverityHigh,
		Tags:               []string{"test-tag"},
		Tests:              []models.UnitTest{},
		Threshold:          10,
	}

	global = &models.Global{
		Body:        "def helper_is_true(truthy): return truthy is True\n",
		Description: "Provides a helper function",
		ID:          "GlobalTypeAnalysis",
	}

	dataModel = &models.DataModel{
		Body:        "def get_source_ip(event): return 'source_ip'\n",
		Description: "Example LogType Schema",
		Enabled:     true,
		ID:          "DataModelTypeAnalysis",
		LogTypes:    []string{"OneLogin.Events"},
		Mappings: []models.DataModelMapping{
			{
				Name: "source_ip",
				Path: "ipAddress",
			},
		},
	}
	dataModelTwo = &models.DataModel{
		Body:        "def get_source_ip(event): return 'source_ip'\n",
		Description: "Example LogType Schema",
		Enabled:     true,
		ID:          "SecondDataModelTypeAnalysis",
		LogTypes:    []string{"Box.Events"},
		Mappings: []models.DataModelMapping{
			{
				Name: "source_ip",
				Path: "ipAddress",
			},
		},
	}
	dataModelDisabled = &models.DataModel{
		Body:        "def get_source_ip(event): return 'source_ip'\n",
		Description: "Example LogType Schema",
		Enabled:     false,
		ID:          "ThirdDataModelTypeAnalysis",
		LogTypes:    []string{"Box.Events"},
		Mappings: []models.DataModelMapping{
			{
				Name: "source_ip",
				Path: "ipAddress",
			},
		},
	}
	dataModels           = [3]*models.DataModel{dataModel, dataModelTwo, dataModelDisabled}
	dataModelFromBulkYML = &models.DataModel{
		Enabled:  true,
		ID:       "Some.Events.DataModel",
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
		t.Run("ListFilteredMultiple", listFilteredMultiple)
		t.Run("ListFilteredNoUser", listFilteredNoUser)
		t.Run("ListPaging", listPaging)
		t.Run("ListProjection", listProjection)
		t.Run("ListRules", listRules)
		t.Run("ListGlobals", listGlobals)
		t.Run("ListDataModels", listDataModels)
		t.Run("ListEnabledDataModels", listEnabledDataModels)
		t.Run("ListSortedDataModels", listSortedDataModels)
		t.Run("ListDetections", listDetections)
		t.Run("ListDetectionsFiltered", listDetectionsFiltered)
		t.Run("ListDetectionsComplianceProjection", listDetectionsComplianceProjection)
		t.Run("ListDetectionsAnalysisTypeFilter", listDetectionsAnalysisTypeFilter)
		t.Run("ListDetectionsComplianceFilter", listDetectionsComplianceFilter)
	})

	t.Run("Modify", func(t *testing.T) {
		t.Run("ModifyNotFound", modifyNotFound)
		t.Run("ModifySuccess", modifySuccess)
		t.Run("ModifyRule", modifyRule)
		t.Run("ModifyGlobal", modifyGlobal)
		t.Run("ModifyDataModel", modifyDataModel)
	})

	t.Run("Suppress", func(t *testing.T) {
		t.Run("SuppressNotFound", suppressNotFound)
		t.Run("SuppressSuccess", suppressSuccess)
	})

	t.Run("Delete", func(t *testing.T) {
		t.Run("DeleteNotExists", deleteNotExists)
		t.Run("DeletePolicies", deletePolicies)
		t.Run("DeleteRules", deleteRules)
		t.Run("DeleteDataModels", deleteDataModels)
		t.Run("DeleteGlobals", deleteGlobals)
	})
}

func testPolicyPass(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		TestPolicy: &models.TestPolicyInput{
			Body:          policy.Body,
			ResourceTypes: []string{"AWS.S3.Bucket"},
			Tests:         policy.Tests,
		},
	}
	expected := models.TestPolicyOutput{
		Results: []models.TestPolicyRecord{
			{
				ID:     "passed-0",
				Name:   input.TestPolicy.Tests[0].Name,
				Passed: true,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
				},
			},
			{
				ID:     "passed-1",
				Name:   input.TestPolicy.Tests[1].Name,
				Passed: true,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
				},
			},
		},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testRulePass(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
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
		Results: []models.TestRuleRecord{
			{
				ID:     "0",
				Name:   input.TestRule.Tests[0].Name,
				Passed: true,
				Functions: models.TestRuleRecordFunctions{
					Rule: &models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
					Dedup: &models.TestDetectionSubRecord{
						Output: aws.String("defaultDedupString:RuleAPITestRule"),
					},
				},
			}, {
				ID:     "1",
				Name:   input.TestRule.Tests[1].Name,
				Passed: true,
				Functions: models.TestRuleRecordFunctions{
					Rule: &models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
					Dedup: &models.TestDetectionSubRecord{
						Output: aws.String("defaultDedupString:RuleAPITestRule"),
					},
				},
			},
		},
	}

	var result models.TestRuleOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testPolicyPassAllResourceTypes(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		TestPolicy: &models.TestPolicyInput{
			Body:          "def policy(resource): return True",
			ResourceTypes: []string{},   // means applicable to all resource types
			Tests:         policy.Tests, // just reuse from the example policy
		},
	}
	expected := models.TestPolicyOutput{
		Results: []models.TestPolicyRecord{
			{
				ID:     "passed-0",
				Name:   input.TestPolicy.Tests[0].Name,
				Passed: true,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
				},
			},
			{
				ID:     "passed-1",
				Name:   input.TestPolicy.Tests[1].Name,
				Passed: true,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
				},
			},
		},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testRulePassAllLogTypes(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
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
		Results: []models.TestRuleRecord{
			{
				ID:     "0",
				Name:   input.TestRule.Tests[0].Name,
				Passed: true,
				Functions: models.TestRuleRecordFunctions{
					Rule: &models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
					Dedup: &models.TestDetectionSubRecord{
						Output: aws.String("defaultDedupString:RuleAPITestRule"),
					},
				},
			},
		},
	}

	var result models.TestRuleOutput
	statusCode, err := apiClient.Invoke(&input, &result)
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
		Results: []models.TestPolicyRecord{
			{
				ID:     "failed-0",
				Name:   input.TestPolicy.Tests[0].Name,
				Passed: false,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"), // expected result
					},
				},
			},
			{
				ID:     "failed-1",
				Name:   input.TestPolicy.Tests[1].Name,
				Passed: false,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
				},
			},
		},
	}

	var result models.TestPolicyOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func testRuleFail(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
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
		Results: []models.TestRuleRecord{
			{
				ID:     "0",
				Name:   input.TestRule.Tests[0].Name,
				Passed: false,
				Functions: models.TestRuleRecordFunctions{
					Rule: &models.TestDetectionSubRecord{
						Output: aws.String("false"),
					},
					Dedup: &models.TestDetectionSubRecord{
						Output: aws.String("defaultDedupString:RuleAPITestRule"),
					},
				},
			},
		},
	}

	var result models.TestRuleOutput
	statusCode, err := apiClient.Invoke(&input, &result)
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
		Results: []models.TestPolicyRecord{
			{
				ID:     "errored-0",
				Name:   input.TestPolicy.Tests[0].Name,
				Passed: false,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"), // expected result
						Error: &models.TestError{
							Message: "SyntaxError: invalid syntax (PolicyApiTestingPolicy.py, line 1)",
						},
					},
				},
			},
			{
				ID:     "errored-1",
				Name:   input.TestPolicy.Tests[1].Name,
				Passed: false,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"),
						Error: &models.TestError{
							Message: "SyntaxError: invalid syntax (PolicyApiTestingPolicy.py, line 1)",
						},
					},
				},
			},
		},
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
					Name:           "test-0",
					Resource:       `{"Hello": true}`,
				},
				{
					ExpectedResult: false,
					Name:           "test-1",
					Resource:       `{"Hello": false}`,
				},
				{
					ExpectedResult: true,
					Name:           "test-2",
					Resource:       `{"Hello": false}`,
				},
				{
					ExpectedResult: true,
					Name:           "test-3",
					Resource:       `{"Goodbye": false}`,
				},
			},
		},
	}
	expected := models.TestPolicyOutput{
		Results: []models.TestPolicyRecord{
			{
				ID:     "passed-0",
				Name:   input.TestPolicy.Tests[0].Name,
				Passed: true,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
				},
			},
			{
				ID:     "passed-1",
				Name:   input.TestPolicy.Tests[1].Name,
				Passed: true,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("false"),
					},
				},
			},
			{
				ID:     "failed-2",
				Name:   input.TestPolicy.Tests[2].Name,
				Passed: false,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"), // expected result
					},
				},
			},
			{
				ID:     "errored-3",
				Name:   input.TestPolicy.Tests[3].Name,
				Passed: false,
				Functions: models.TestPolicyRecordFunctions{
					Policy: models.TestDetectionSubRecord{
						Output: aws.String("true"), // expected result
						Error:  &models.TestError{Message: "KeyError: 'Hello'"},
					},
				},
			},
		},
	}

	var result models.TestPolicyOutput
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
			AutoRemediationID:         policy.AutoRemediationID,
			AutoRemediationParameters: policy.AutoRemediationParameters,
			Body:                      policy.Body,
			Description:               policy.Description,
			DisplayName:               policy.DisplayName,
			Enabled:                   policy.Enabled,
			ID:                        policy.ID,
			OutputIDs:                 policy.OutputIDs,
			ResourceTypes:             policy.ResourceTypes,
			Severity:                  policy.Severity,
			Suppressions:              policy.Suppressions,
			Tags:                      policy.Tags,
			Tests:                     policy.Tests,
			UserID:                    userID,
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
	defer batchDeletePolicies(t, policyID)

	req := models.UpdatePolicyInput{
		Body:     "def policy(resource): return resource['key']",
		Enabled:  true,
		ID:       policyID,
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
		UserID: userID,
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
	defer batchDeletePolicies(t, policyID)

	req := models.UpdatePolicyInput{
		Body:     "def policy(resource): return True",
		Enabled:  false,
		ID:       policyID,
		Severity: policy.Severity,
		Tests: []models.UnitTest{
			{
				Name:           "This will fail",
				ExpectedResult: false,
				Resource:       `{}`,
			},
		},
		UserID: userID,
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
	defer batchDeletePolicies(t, policyID)

	req := models.UpdatePolicyInput{
		Body:     "def policy(resource): return True",
		Enabled:  true,
		ID:       policyID,
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
		UserID: userID,
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
	defer batchDeletePolicies(t, policyID)

	req := models.UpdatePolicyInput{
		Body:     "def policy(resource): return True",
		Enabled:  true,
		ID:       policyID,
		Severity: policy.Severity,
		Tests: []models.UnitTest{
			{
				Name:           "PolicyName",
				ExpectedResult: true,
				Resource:       "invalid json",
			},
		},
		UserID: userID,
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
	defer batchDeleteRules(t, ruleID)

	req := models.UpdateRuleInput{
		Body:     "def rule(event): return event['key']",
		Enabled:  true,
		ID:       ruleID,
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
		UserID: userID,
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
	defer batchDeleteRules(t, ruleID)

	req := models.UpdateRuleInput{
		Body:     "def rule(event): return True",
		Enabled:  true,
		ID:       ruleID,
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
		UserID: userID,
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
	defer batchDeleteRules(t, ruleID)

	req := models.UpdateRuleInput{
		Body:     "def rule(event): return True",
		Enabled:  true,
		ID:       ruleID,
		Severity: rule.Severity,
		Tests: []models.UnitTest{
			{
				Name:           "Trigger alert",
				ExpectedResult: true,
				Resource:       "invalid json",
			},
		},
		UserID: userID,
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
	defer batchDeleteRules(t, ruleID)

	req := models.UpdateRuleInput{
		Body:     "def rule(event): return True",
		Enabled:  false,
		ID:       ruleID,
		Severity: rule.Severity,
		Tests: []models.UnitTest{
			{
				Name:           "This will fail",
				ExpectedResult: false,
				Resource:       `{}`,
			},
		},
		UserID: userID,
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
			Body:               rule.Body,
			DedupPeriodMinutes: rule.DedupPeriodMinutes,
			Description:        rule.Description,
			Enabled:            rule.Enabled,
			ID:                 rule.ID,
			LogTypes:           rule.LogTypes,
			OutputIDs:          rule.OutputIDs,
			Severity:           rule.Severity,
			Tags:               rule.Tags,
			Threshold:          rule.Threshold,
			UserID:             userID,
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
			Body:        global.Body,
			Description: global.Description,
			ID:          global.ID,
			UserID:      userID,
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
		GetPolicy: &models.GetPolicyInput{ID: "does-not-exist"},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

// Get the latest policy version (from Dynamo)
func getLatest(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetPolicy: &models.GetPolicyInput{ID: policy.ID},
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
		GetPolicy: &models.GetPolicyInput{ID: policy.ID},
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
		GetRule: &models.GetRuleInput{ID: rule.ID},
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
		GetDataModel: &models.GetDataModelInput{ID: dataModel.ID},
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
		GetGlobal: &models.GetGlobalInput{ID: global.ID},
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
		GetRule: &models.GetRuleInput{ID: policy.ID},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

func modifyNotFound(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		UpdatePolicy: &models.UpdatePolicyInput{
			Body:     "def policy(resource): return False",
			Enabled:  policy.Enabled,
			ID:       "DOES.NOT.EXIST",
			Severity: policy.Severity,
			UserID:   userID,
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
			AutoRemediationID:         policy.AutoRemediationID,
			AutoRemediationParameters: policy.AutoRemediationParameters,
			Body:                      policy.Body,
			Description:               expectedPolicy.Description,
			DisplayName:               policy.DisplayName,
			Enabled:                   policy.Enabled,
			ID:                        policy.ID,
			OutputIDs:                 policy.OutputIDs,
			Reference:                 policy.Reference,
			Reports:                   policy.Reports,
			ResourceTypes:             policy.ResourceTypes,
			Runbook:                   policy.Runbook,
			Severity:                  policy.Severity,
			Suppressions:              policy.Suppressions,
			Tags:                      policy.Tags,
			Tests:                     expectedPolicy.Tests,
			UserID:                    userID,
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
			Body:               rule.Body,
			DedupPeriodMinutes: expectedRule.DedupPeriodMinutes,
			Description:        expectedRule.Description,
			DisplayName:        rule.DisplayName,
			Enabled:            rule.Enabled,
			ID:                 rule.ID,
			LogTypes:           rule.LogTypes,
			OutputIDs:          rule.OutputIDs,
			Reference:          rule.Reference,
			Reports:            rule.Reports,
			Runbook:            rule.Runbook,
			Severity:           rule.Severity,
			Tags:               rule.Tags,
			Tests:              rule.Tests,
			Threshold:          expectedRule.Threshold,
			UserID:             userID,
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
			Body:        global.Body,
			Description: global.Description,
			ID:          global.ID,
			Tags:        global.Tags,
			UserID:      userID,
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

func suppressNotFound(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		Suppress: &models.SuppressInput{
			PolicyIDs:        []string{"no-such-id"},
			ResourcePatterns: []string{"s3:.*"},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	// a policy which doesn't exist logs a warning but doesn't return an API error
	assert.Equal(t, http.StatusOK, statusCode)
}

func suppressSuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		Suppress: &models.SuppressInput{
			PolicyIDs:        []string{policy.ID},
			ResourcePatterns: []string{"new-suppression", "and-another"},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Verify suppressions were added correctly
	input = models.LambdaInput{
		GetPolicy: &models.GetPolicyInput{ID: policy.ID},
	}
	var result models.Policy
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	sort.Strings(result.Suppressions)
	// It was added to the existing suppressions
	assert.Equal(t, []string{"and-another", "new-suppression", "panther.*"}, result.Suppressions)
}

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
	defer batchDeleteRules(t, "Rule.Always.True")

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
		GetPolicy: &models.GetPolicyInput{ID: policy.ID},
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
	input.GetPolicy.ID = policyFromBulk.ID
	_, err = apiClient.Invoke(&input, &policyFromBulk)
	require.NoError(t, err)

	assert.NotZero(t, policyFromBulk.CreatedAt)
	assert.NotZero(t, policyFromBulk.LastModified)

	cloudtrailBody, err := ioutil.ReadFile(path.Join(analysesRoot, "policy_aws_cloudtrail_log_validation_enabled.py"))
	require.NoError(t, err)
	assert.Equal(t, policyFromBulk.Body, string(cloudtrailBody))
	assert.Len(t, policyFromBulk.Tests, 2)

	// Verify newly created policy #2
	input.GetPolicy.ID = policyFromBulkJSON.ID
	_, err = apiClient.Invoke(&input, &policyFromBulkJSON)
	require.NoError(t, err)
	assert.Equal(t, "Matches every resource", policyFromBulkJSON.Description)
	assert.Equal(t, "Test:Policy:JSON", policyFromBulkJSON.ID)

	// Verify newly created Rule
	expectedNewRule := models.Rule{
		AnalysisType:       models.TypeRule,
		DedupPeriodMinutes: 480,
		Description:        "Test rule",
		DisplayName:        "Rule Always True display name",
		Enabled:            true,
		ID:                 "Rule.Always.True",
		LogTypes:           []string{"CiscoUmbrella.DNS"},
		OutputIDs:          []string{},
		Reports:            map[string][]string{},
		Runbook:            "Test runbook",
		Severity:           compliancemodels.SeverityLow,
		Tags:               []string{"DNS"},
		Tests:              []models.UnitTest{},
		Threshold:          42,
	}

	input = models.LambdaInput{
		GetRule: &models.GetRuleInput{ID: expectedNewRule.ID},
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
		GetDataModel: &models.GetDataModelInput{ID: dataModelFromBulkYML.ID},
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
			Severity:       []compliancemodels.Severity{compliancemodels.SeverityMedium},
			CreatedBy:      userID,
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

func listFilteredNoUser(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{
			Enabled:        aws.Bool(true),
			HasRemediation: aws.Bool(true),
			NameContains:   "json", // policyFromBulkJSON only
			ResourceTypes:  []string{"AWS.S3.Bucket"},
			Severity:       []compliancemodels.Severity{compliancemodels.SeverityMedium},
			CreatedBy:      "nil",
		},
	}
	var result models.ListPoliciesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListPoliciesOutput{
		Paging: models.Paging{
			ThisPage:   0,
			TotalItems: 0,
			TotalPages: 0,
		},
		Policies: []models.Policy{},
	}
	assert.Equal(t, expected, result)
}

func listFilteredMultiple(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{
			Enabled:        aws.Bool(true),
			HasRemediation: aws.Bool(true),
			NameContains:   "json", // policyFromBulkJSON only
			ResourceTypes:  []string{"AWS.S3.Bucket"},
			Severity:       []compliancemodels.Severity{compliancemodels.SeverityLow, compliancemodels.SeverityMedium},
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
		AnalysisType:              models.TypePolicy,
		AutoRemediationParameters: map[string]string{},
		OutputIDs:                 []string{},
		Reports:                   map[string][]string{},
		ResourceTypes:             []string{},
		Suppressions:              []string{},
		Tags:                      []string{},
		Tests:                     []models.UnitTest{},
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
			TotalItems: 4,
			TotalPages: 1,
		},
		Models: []models.DataModel{
			*dataModel, *dataModelTwo, *dataModelFromBulkYML, *dataModelDisabled,
		},
	}
	assert.Equal(t, expected, result)
}

func listEnabledDataModels(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDataModels: &models.ListDataModelsInput{
			Enabled: aws.Bool(true),
		},
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

func listSortedDataModels(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDataModels: &models.ListDataModelsInput{
			SortBy: "enabled",
		},
	}
	var result models.ListDataModelsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListDataModelsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 4,
			TotalPages: 1,
		},
		Models: []models.DataModel{
			*dataModel, *dataModelTwo, *dataModelFromBulkYML, *dataModelDisabled,
		},
	}
	assert.Equal(t, expected, result)

	input = models.LambdaInput{
		ListDataModels: &models.ListDataModelsInput{
			SortBy: "lastModified",
		},
	}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected = models.ListDataModelsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 4,
			TotalPages: 1,
		},
		Models: []models.DataModel{
			*dataModel, *dataModelTwo, *dataModelDisabled, *dataModelFromBulkYML,
		},
	}
	assert.Equal(t, expected, result)
}

func listDetections(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDetections: &models.ListDetectionsInput{
			SortBy: "id",
		},
	}
	var result models.ListDetectionsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListDetectionsOutput{
		Paging: models.Paging{
			ThisPage: 1,
			// 3 policies, 1 rule
			TotalItems: 4,
			TotalPages: 1,
		},
		// Expected:
		// AWS.CloudTrail.Log.Validation.Enabled
		// NonEmptyEvent
		// Test:Policy
		// Test:Policy:JSON

		// Actual
		// Test:Policy - AlwaysTrue
		// Test:Policy:JSON
		// AWS.CloudTrail.Log.Validation.Enabled
		// NonEmptyEvent
		Detections: []models.Detection{
			{
				AutoRemediationID:         policyFromBulk.AutoRemediationID,
				AutoRemediationParameters: policyFromBulk.AutoRemediationParameters,
				ComplianceStatus:          policyFromBulk.ComplianceStatus,
				Suppressions:              policyFromBulk.Suppressions,
				AnalysisType:              models.TypePolicy,
				ResourceTypes:             policyFromBulk.ResourceTypes,
				LogTypes:                  []string{},
				Body:                      policyFromBulk.Body,
				CreatedAt:                 policyFromBulk.CreatedAt,
				CreatedBy:                 policyFromBulk.CreatedBy,
				Description:               policyFromBulk.Description,
				DisplayName:               policyFromBulk.DisplayName,
				Enabled:                   policyFromBulk.Enabled,
				ID:                        policyFromBulk.ID,
				LastModified:              policyFromBulk.LastModified,
				LastModifiedBy:            policyFromBulk.LastModifiedBy,
				OutputIDs:                 policyFromBulk.OutputIDs,
				Reference:                 policyFromBulk.Reference,
				Reports:                   policyFromBulk.Reports,
				Runbook:                   policyFromBulk.Runbook,
				Severity:                  policyFromBulk.Severity,
				Tags:                      policyFromBulk.Tags,
				Tests:                     policyFromBulk.Tests,
				VersionID:                 policyFromBulk.VersionID,
			},
			{
				AutoRemediationParameters: make(map[string]string),
				Suppressions:              []string{},
				DedupPeriodMinutes:        rule.DedupPeriodMinutes,
				Threshold:                 rule.Threshold,
				AnalysisType:              models.TypeRule,
				ResourceTypes:             []string{},
				LogTypes:                  rule.LogTypes,
				Body:                      rule.Body,
				CreatedAt:                 rule.CreatedAt,
				CreatedBy:                 rule.CreatedBy,
				Description:               rule.Description,
				DisplayName:               rule.DisplayName,
				Enabled:                   rule.Enabled,
				ID:                        rule.ID,
				LastModified:              rule.LastModified,
				LastModifiedBy:            rule.LastModifiedBy,
				OutputIDs:                 rule.OutputIDs,
				Reference:                 rule.Reference,
				Reports:                   rule.Reports,
				Runbook:                   rule.Runbook,
				Severity:                  rule.Severity,
				Tags:                      rule.Tags,
				Tests:                     rule.Tests,
				VersionID:                 rule.VersionID,
			},
			{
				AutoRemediationID:         policy.AutoRemediationID,
				AutoRemediationParameters: policy.AutoRemediationParameters,
				ComplianceStatus:          policy.ComplianceStatus,
				Suppressions:              policy.Suppressions,
				AnalysisType:              models.TypePolicy,
				ResourceTypes:             policy.ResourceTypes,
				LogTypes:                  []string{},
				Body:                      policy.Body,
				CreatedAt:                 policy.CreatedAt,
				CreatedBy:                 policy.CreatedBy,
				Description:               policy.Description,
				DisplayName:               policy.DisplayName,
				Enabled:                   policy.Enabled,
				ID:                        policy.ID,
				LastModified:              policy.LastModified,
				LastModifiedBy:            policy.LastModifiedBy,
				OutputIDs:                 policy.OutputIDs,
				Reference:                 policy.Reference,
				Reports:                   policy.Reports,
				Runbook:                   policy.Runbook,
				Severity:                  policy.Severity,
				Tags:                      policy.Tags,
				Tests:                     policy.Tests,
				VersionID:                 policy.VersionID,
			},
			{
				AutoRemediationID:         policyFromBulkJSON.AutoRemediationID,
				AutoRemediationParameters: policyFromBulkJSON.AutoRemediationParameters,
				ComplianceStatus:          policyFromBulkJSON.ComplianceStatus,
				Suppressions:              policyFromBulkJSON.Suppressions,
				AnalysisType:              models.TypePolicy,
				ResourceTypes:             policyFromBulkJSON.ResourceTypes,
				LogTypes:                  []string{},
				Body:                      policyFromBulkJSON.Body,
				CreatedAt:                 policyFromBulkJSON.CreatedAt,
				CreatedBy:                 policyFromBulkJSON.CreatedBy,
				Description:               policyFromBulkJSON.Description,
				DisplayName:               policyFromBulkJSON.DisplayName,
				Enabled:                   policyFromBulkJSON.Enabled,
				ID:                        policyFromBulkJSON.ID,
				LastModified:              policyFromBulkJSON.LastModified,
				LastModifiedBy:            policyFromBulkJSON.LastModifiedBy,
				OutputIDs:                 policyFromBulkJSON.OutputIDs,
				Reference:                 policyFromBulkJSON.Reference,
				Reports:                   policyFromBulkJSON.Reports,
				Runbook:                   policyFromBulkJSON.Runbook,
				Severity:                  policyFromBulkJSON.Severity,
				Tags:                      policyFromBulkJSON.Tags,
				Tests:                     policyFromBulkJSON.Tests,
				VersionID:                 policyFromBulkJSON.VersionID,
			},
		},
	}
	assert.Equal(t, expected, result)
}

func listDetectionsFiltered(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDetections: &models.ListDetectionsInput{
			Enabled:        aws.Bool(true),
			HasRemediation: aws.Bool(true),
			NameContains:   "json", // policyFromBulkJSON only
			ResourceTypes:  []string{"AWS.S3.Bucket"},
			Severity:       []compliancemodels.Severity{compliancemodels.SeverityMedium},
			CreatedBy:      userID,
			SortBy:         "id",
		},
	}
	var result models.ListDetectionsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListDetectionsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 1,
			TotalPages: 1,
		},
		Detections: []models.Detection{
			{
				AutoRemediationID:         policyFromBulkJSON.AutoRemediationID,
				AutoRemediationParameters: policyFromBulkJSON.AutoRemediationParameters,
				ComplianceStatus:          policyFromBulkJSON.ComplianceStatus,
				Suppressions:              policyFromBulkJSON.Suppressions,
				AnalysisType:              models.TypePolicy,
				ResourceTypes:             policyFromBulkJSON.ResourceTypes,
				LogTypes:                  []string{},
				Body:                      policyFromBulkJSON.Body,
				CreatedAt:                 policyFromBulkJSON.CreatedAt,
				CreatedBy:                 policyFromBulkJSON.CreatedBy,
				Description:               policyFromBulkJSON.Description,
				DisplayName:               policyFromBulkJSON.DisplayName,
				Enabled:                   policyFromBulkJSON.Enabled,
				ID:                        policyFromBulkJSON.ID,
				LastModified:              policyFromBulkJSON.LastModified,
				LastModifiedBy:            policyFromBulkJSON.LastModifiedBy,
				OutputIDs:                 policyFromBulkJSON.OutputIDs,
				Reference:                 policyFromBulkJSON.Reference,
				Reports:                   policyFromBulkJSON.Reports,
				Runbook:                   policyFromBulkJSON.Runbook,
				Severity:                  policyFromBulkJSON.Severity,
				Tags:                      policyFromBulkJSON.Tags,
				Tests:                     policyFromBulkJSON.Tests,
				VersionID:                 policyFromBulkJSON.VersionID,
			},
		},
	}
	assert.Equal(t, expected, result)
}

func listDetectionsComplianceProjection(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDetections: &models.ListDetectionsInput{
			// Select only a subset of fields
			Fields: []string{"id", "displayName", "complianceStatus"},
			SortBy: "id",
		},
	}
	var result models.ListDetectionsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Empty lists/maps will always be initialized in the response
	emptyPolicy := models.Detection{
		AutoRemediationParameters: map[string]string{},
		OutputIDs:                 []string{},
		Reports:                   map[string][]string{},
		ResourceTypes:             []string{},
		LogTypes:                  []string{},
		Suppressions:              []string{},
		Tags:                      []string{},
		Tests:                     []models.UnitTest{},
	}

	firstItem := emptyPolicy
	firstItem.AnalysisType = models.TypePolicy
	firstItem.ID = policyFromBulk.ID
	firstItem.DisplayName = policyFromBulk.DisplayName
	firstItem.ComplianceStatus = policyFromBulk.ComplianceStatus

	secondItem := emptyPolicy
	secondItem.AnalysisType = models.TypePolicy
	secondItem.ID = policy.ID
	secondItem.DisplayName = policy.DisplayName
	secondItem.ComplianceStatus = policy.ComplianceStatus

	thirdItem := emptyPolicy
	thirdItem.AnalysisType = models.TypePolicy
	thirdItem.ID = policyFromBulkJSON.ID
	thirdItem.DisplayName = policyFromBulkJSON.DisplayName
	thirdItem.ComplianceStatus = policyFromBulkJSON.ComplianceStatus

	fourthItem := emptyPolicy
	fourthItem.AnalysisType = models.TypeRule
	fourthItem.ID = rule.ID
	fourthItem.DisplayName = rule.DisplayName

	expected := models.ListDetectionsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 4,
			TotalPages: 1,
		},
		Detections: []models.Detection{firstItem, fourthItem, secondItem, thirdItem},
	}
	assert.Equal(t, expected, result)
}

func listDetectionsAnalysisTypeFilter(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDetections: &models.ListDetectionsInput{
			AnalysisTypes: []models.DetectionType{models.TypeRule},
			SortBy:        "id",
		},
	}
	var result models.ListDetectionsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListDetectionsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 1,
			TotalPages: 1,
		},
		Detections: []models.Detection{
			{
				AutoRemediationParameters: make(map[string]string),
				Suppressions:              []string{},
				DedupPeriodMinutes:        rule.DedupPeriodMinutes,
				Threshold:                 rule.Threshold,
				AnalysisType:              models.TypeRule,
				ResourceTypes:             []string{},
				LogTypes:                  rule.LogTypes,
				Body:                      rule.Body,
				CreatedAt:                 rule.CreatedAt,
				CreatedBy:                 rule.CreatedBy,
				Description:               rule.Description,
				DisplayName:               rule.DisplayName,
				Enabled:                   rule.Enabled,
				ID:                        rule.ID,
				LastModified:              rule.LastModified,
				LastModifiedBy:            rule.LastModifiedBy,
				OutputIDs:                 rule.OutputIDs,
				Reference:                 rule.Reference,
				Reports:                   rule.Reports,
				Runbook:                   rule.Runbook,
				Severity:                  rule.Severity,
				Tags:                      rule.Tags,
				Tests:                     rule.Tests,
				VersionID:                 rule.VersionID,
			},
		},
	}
	assert.Equal(t, expected, result)

	input = models.LambdaInput{
		ListDetections: &models.ListDetectionsInput{
			AnalysisTypes: []models.DetectionType{models.TypePolicy},
			SortBy:        "id",
		},
	}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected = models.ListDetectionsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 1,
		},
		Detections: []models.Detection{
			{
				AutoRemediationID:         policyFromBulk.AutoRemediationID,
				AutoRemediationParameters: policyFromBulk.AutoRemediationParameters,
				ComplianceStatus:          policyFromBulk.ComplianceStatus,
				Suppressions:              policyFromBulk.Suppressions,
				AnalysisType:              models.TypePolicy,
				ResourceTypes:             policyFromBulk.ResourceTypes,
				LogTypes:                  []string{},
				Body:                      policyFromBulk.Body,
				CreatedAt:                 policyFromBulk.CreatedAt,
				CreatedBy:                 policyFromBulk.CreatedBy,
				Description:               policyFromBulk.Description,
				DisplayName:               policyFromBulk.DisplayName,
				Enabled:                   policyFromBulk.Enabled,
				ID:                        policyFromBulk.ID,
				LastModified:              policyFromBulk.LastModified,
				LastModifiedBy:            policyFromBulk.LastModifiedBy,
				OutputIDs:                 policyFromBulk.OutputIDs,
				Reference:                 policyFromBulk.Reference,
				Reports:                   policyFromBulk.Reports,
				Runbook:                   policyFromBulk.Runbook,
				Severity:                  policyFromBulk.Severity,
				Tags:                      policyFromBulk.Tags,
				Tests:                     policyFromBulk.Tests,
				VersionID:                 policyFromBulk.VersionID,
			},
			{
				AutoRemediationID:         policy.AutoRemediationID,
				AutoRemediationParameters: policy.AutoRemediationParameters,
				ComplianceStatus:          policy.ComplianceStatus,
				Suppressions:              policy.Suppressions,
				AnalysisType:              models.TypePolicy,
				ResourceTypes:             policy.ResourceTypes,
				LogTypes:                  []string{},
				Body:                      policy.Body,
				CreatedAt:                 policy.CreatedAt,
				CreatedBy:                 policy.CreatedBy,
				Description:               policy.Description,
				DisplayName:               policy.DisplayName,
				Enabled:                   policy.Enabled,
				ID:                        policy.ID,
				LastModified:              policy.LastModified,
				LastModifiedBy:            policy.LastModifiedBy,
				OutputIDs:                 policy.OutputIDs,
				Reference:                 policy.Reference,
				Reports:                   policy.Reports,
				Runbook:                   policy.Runbook,
				Severity:                  policy.Severity,
				Tags:                      policy.Tags,
				Tests:                     policy.Tests,
				VersionID:                 policy.VersionID,
			},
			{
				AutoRemediationID:         policyFromBulkJSON.AutoRemediationID,
				AutoRemediationParameters: policyFromBulkJSON.AutoRemediationParameters,
				ComplianceStatus:          policyFromBulkJSON.ComplianceStatus,
				Suppressions:              policyFromBulkJSON.Suppressions,
				AnalysisType:              models.TypePolicy,
				ResourceTypes:             policyFromBulkJSON.ResourceTypes,
				LogTypes:                  []string{},
				Body:                      policyFromBulkJSON.Body,
				CreatedAt:                 policyFromBulkJSON.CreatedAt,
				CreatedBy:                 policyFromBulkJSON.CreatedBy,
				Description:               policyFromBulkJSON.Description,
				DisplayName:               policyFromBulkJSON.DisplayName,
				Enabled:                   policyFromBulkJSON.Enabled,
				ID:                        policyFromBulkJSON.ID,
				LastModified:              policyFromBulkJSON.LastModified,
				LastModifiedBy:            policyFromBulkJSON.LastModifiedBy,
				OutputIDs:                 policyFromBulkJSON.OutputIDs,
				Reference:                 policyFromBulkJSON.Reference,
				Reports:                   policyFromBulkJSON.Reports,
				Runbook:                   policyFromBulkJSON.Runbook,
				Severity:                  policyFromBulkJSON.Severity,
				Tags:                      policyFromBulkJSON.Tags,
				Tests:                     policyFromBulkJSON.Tests,
				VersionID:                 policyFromBulkJSON.VersionID,
			},
		},
	}
	assert.Equal(t, expected, result)
}

func listDetectionsComplianceFilter(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListDetections: &models.ListDetectionsInput{
			// Select only a subset of fields
			Fields:           []string{"id", "displayName", "complianceStatus"},
			ComplianceStatus: compliancemodels.StatusPass,
			SortBy:           "id",
		},
	}
	var result models.ListDetectionsOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Empty lists/maps will always be initialized in the response
	emptyDetection := models.Detection{
		AutoRemediationParameters: map[string]string{},
		OutputIDs:                 []string{},
		Reports:                   map[string][]string{},
		ResourceTypes:             []string{},
		LogTypes:                  []string{},
		Suppressions:              []string{},
		Tags:                      []string{},
		Tests:                     []models.UnitTest{},
	}

	firstItem := emptyDetection
	firstItem.AnalysisType = models.TypePolicy
	firstItem.ID = policyFromBulk.ID
	firstItem.DisplayName = policyFromBulk.DisplayName
	firstItem.ComplianceStatus = policyFromBulk.ComplianceStatus

	secondItem := emptyDetection
	secondItem.AnalysisType = models.TypePolicy
	secondItem.ID = policy.ID
	secondItem.DisplayName = policy.DisplayName
	secondItem.ComplianceStatus = policy.ComplianceStatus

	thirdItem := emptyDetection
	thirdItem.AnalysisType = models.TypePolicy
	thirdItem.ID = policyFromBulkJSON.ID
	thirdItem.DisplayName = policyFromBulkJSON.DisplayName
	thirdItem.ComplianceStatus = policyFromBulkJSON.ComplianceStatus

	expected := models.ListDetectionsOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 1,
		},
		Detections: []models.Detection{firstItem, secondItem, thirdItem},
	}
	assert.Equal(t, expected, result)
}

// Delete a set of policies that don't exist - returns OK
func deleteNotExists(t *testing.T) {
	t.Parallel()
	batchDeletePolicies(t, "does-not-exist", "also-does-not-exist")
}

func deletePolicies(t *testing.T) {
	t.Parallel()
	batchDeletePolicies(t, policy.ID, policyFromBulk.ID, policyFromBulkJSON.ID)

	// Trying to retrieve the deleted policy should now return 404
	input := models.LambdaInput{
		GetPolicy: &models.GetPolicyInput{ID: policy.ID},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)

	// But retrieving an older version will still work
	input.GetPolicy = &models.GetPolicyInput{
		ID:        versionedPolicy.ID,
		VersionID: versionedPolicy.VersionID,
	}
	var result models.Policy
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, *versionedPolicy, result)

	// List operation should be empty
	input = models.LambdaInput{
		ListPolicies: &models.ListPoliciesInput{},
	}
	var policies models.ListPoliciesOutput

	expected := models.ListPoliciesOutput{Policies: []models.Policy{}}
	statusCode, err = apiClient.Invoke(&input, &policies)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, policies)
}

func deleteRules(t *testing.T) {
	t.Parallel()
	batchDeleteRules(t, rule.ID)

	// Trying to retrieve the deleted rule should now return 404
	input := models.LambdaInput{
		GetRule: &models.GetRuleInput{ID: rule.ID},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)

	// List operation should be empty
	input = models.LambdaInput{
		ListRules: &models.ListRulesInput{},
	}
	var result models.ListRulesOutput
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, models.ListRulesOutput{Rules: []models.Rule{}}, result)
}

func deleteDataModels(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DeleteDataModels: &models.DeleteDataModelsInput{
			Entries: make([]models.DeleteEntry, 0, len(dataModels)+1),
		},
	}
	for _, model := range dataModels {
		input.DeleteDataModels.Entries = append(
			input.DeleteDataModels.Entries, models.DeleteEntry{ID: model.ID})
	}
	input.DeleteDataModels.Entries = append(
		input.DeleteDataModels.Entries, models.DeleteEntry{ID: dataModelFromBulkYML.ID})

	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// List operation should be empty
	input = models.LambdaInput{
		ListDataModels: &models.ListDataModelsInput{},
	}
	var result models.ListDataModelsOutput

	expected := models.ListDataModelsOutput{Models: []models.DataModel{}}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func deleteGlobals(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DeleteGlobals: &models.DeleteGlobalsInput{
			Entries: []models.DeleteEntry{{ID: global.ID}},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Trying to retrieve the deleted policy should now return 404
	input = models.LambdaInput{
		GetGlobal: &models.GetGlobalInput{ID: global.ID},
	}
	statusCode, err = apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)

	// List operation is empty
	input = models.LambdaInput{
		ListGlobals: &models.ListGlobalsInput{},
	}
	var result models.ListGlobalsOutput

	expected := models.ListGlobalsOutput{Globals: []models.Global{}}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, expected, result)
}

func batchDeletePolicies(t *testing.T, policyID ...string) {
	input := models.LambdaInput{
		DeletePolicies: &models.DeletePoliciesInput{
			Entries: make([]models.DeleteEntry, len(policyID)),
		},
	}

	for i, pid := range policyID {
		input.DeletePolicies.Entries[i].ID = pid
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
}

func batchDeleteRules(t *testing.T, ruleID ...string) {
	input := models.LambdaInput{
		DeleteRules: &models.DeleteRulesInput{
			Entries: make([]models.DeleteEntry, len(ruleID)),
		},
	}

	for i, pid := range ruleID {
		input.DeleteRules.Entries[i].ID = pid
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
}
