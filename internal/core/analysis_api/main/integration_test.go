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
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	bootstrapStack      = "panther-bootstrap"
	gatewayStack        = "panther-bootstrap-gateway"
	tableName           = "panther-analysis"
	policiesRoot        = "./test_policies"
	policiesZipLocation = "./bulk_upload.zip"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	httpClient      = gatewayapi.GatewayClient(awsSession)
	apiClient       *client.PantherAnalysis

	userID = models.UserID("521a1c7b-273f-4a03-99a7-5c661de5b0e8")

	// NOTE: this gets changed by the bulk upload!
	policy = &models.Policy{
		AutoRemediationID:         "fix-it",
		AutoRemediationParameters: map[string]string{"hello": "world", "emptyParameter": ""},
		ComplianceStatus:          models.ComplianceStatusPASS,
		Description:               "Matches every resource",
		DisplayName:               "AlwaysTrue",
		Enabled:                   true,
		ID:                        "Test:Policy",
		ResourceTypes:             []string{"AWS.S3.Bucket"},
		Severity:                  "MEDIUM",
		Suppressions:              models.Suppressions{"panther.*"},
		Tags:                      []string{"policyTag"},
		Tests: []*models.UnitTest{
			{
				Name:           "This will be True",
				ResourceType:   "AWS.S3.Bucket",
				ExpectedResult: true,
				Resource:       `{}`,
			},
			{
				Name:           "This will also be True",
				ResourceType:   "AWS.S3.Bucket",
				ExpectedResult: true,
				Resource:       `{"nested": {}}`,
			},
		},
		Reports: map[string][]string{},
	}
	versionedPolicy *models.Policy // this will get set when we modify policy for use in delete testing

	policyFromBulk = &models.Policy{
		AutoRemediationParameters: map[string]string{"hello": "goodbye"},
		ComplianceStatus:          models.ComplianceStatusPASS,
		CreatedBy:                 userID,
		ID:                        "AWS.CloudTrail.Log.Validation.Enabled",
		Enabled:                   true,
		ResourceTypes:             []string{"AWS.CloudTrail"},
		LastModifiedBy:            userID,
		Tags:                      []string{"AWS Managed Rules - Management and Governance", "CIS"},
		Reports:                   map[string][]string{},
		Reference:                 "reference.link",
		Runbook:                   "Runbook\n",
		Severity:                  "MEDIUM",
		Description:               "This rule validates that AWS CloudTrails have log file validation enabled.\n",
		Tests: []*models.UnitTest{
			{
				Name:           "Log File Validation Disabled",
				ResourceType:   "AWS.CloudTrail",
				ExpectedResult: false,
				Resource: `{
        "Info": {
          "LogFileValidationEnabled": false
        },
        "EventSelectors": [
          {
            "DataResources": [
              {
                "Type": "AWS::S3::Object",
                "Values": null
              }
            ],
            "IncludeManagementEvents": false,
            "ReadWriteType": "All"
          }
        ]
      }`,
			},
			{
				Name:           "Log File Validation Enabled",
				ResourceType:   "AWS.CloudTrail",
				ExpectedResult: true,
				Resource: `{
        "Info": {
          "LogFileValidationEnabled": true
        },
        "Bucket": {
          "CreationDate": "2019-01-01T00:00:00Z",
          "Grants": [
            {
              "Grantee": {
                "URI": null
              },
              "Permission": "FULL_CONTROL"
            }
          ],
          "Owner": {
            "DisplayName": "panther-admins",
            "ID": "longalphanumericstring112233445566778899"
          },
          "Versioning": null
        },
        "EventSelectors": [
          {
            "DataResources": [
              {
                "Type": "AWS::S3::Object",
                "Values": null
              }
            ],
            "ReadWriteType": "All"
          }
        ]
      }`,
			},
		},
	}

	policyFromBulkJSON = &models.Policy{
		AutoRemediationID:         "fix-it",
		AutoRemediationParameters: map[string]string{"hello": "goodbye"},
		ComplianceStatus:          models.ComplianceStatusPASS,
		CreatedBy:                 userID,
		Description:               "Matches every resource",
		DisplayName:               "AlwaysTrue",
		Enabled:                   true,
		ID:                        "Test:Policy:JSON",
		LastModifiedBy:            userID,
		ResourceTypes:             []string{"AWS.S3.Bucket"},
		Severity:                  "MEDIUM",
		Suppressions:              []string{},
		Tags:                      []string{},
		Reports:                   map[string][]string{},
		Tests: []*models.UnitTest{
			{
				Name:           "This will be True",
				ResourceType:   "AWS.S3.Bucket",
				ExpectedResult: true,
				Resource:       `{"Bucket": "empty"}`,
			},
		},
	}

	rule = &models.Rule{
		Body:               "def rule(event): return len(event) > 0\n",
		Description:        "Matches every non-empty event",
		Enabled:            true,
		ID:                 "NonEmptyEvent",
		LogTypes:           []string{"AWS.CloudTrail"},
		Severity:           "HIGH",
		Tests:              []*models.UnitTest{},
		Tags:               []string{"test-tag"},
		Reports:            map[string][]string{},
		DedupPeriodMinutes: 1440,
	}

	global = &models.Global{
		Body:        "def helper_is_true(truthy): return truthy is True\n",
		Description: "Provides a helper function",
		ID:          "GlobalTypeAnalysis",
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

	// Set expected bodies from test files
	trueBody, err := ioutil.ReadFile(path.Join(policiesRoot, "always_true.py"))
	require.NoError(t, err)
	policy.Body = models.Body(trueBody)
	policyFromBulkJSON.Body = models.Body(trueBody)

	cloudtrailBody, err := ioutil.ReadFile(path.Join(policiesRoot, "aws_cloudtrail_log_validation_enabled.py"))
	require.NoError(t, err)
	policyFromBulk.Body = models.Body(cloudtrailBody)

	// Lookup analysis bucket name
	cfnClient := cloudformation.New(awsSession)
	response, err := cfnClient.DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String(bootstrapStack)})
	require.NoError(t, err)
	var bucketName string
	for _, output := range response.Stacks[0].Outputs {
		if aws.StringValue(output.OutputKey) == "AnalysisVersionsBucket" {
			bucketName = *output.OutputValue
			break
		}
	}
	require.NotEmpty(t, bucketName)

	// Lookup analysis-api endpoint
	response, err = cfnClient.DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String(gatewayStack)})
	require.NoError(t, err)
	var endpoint string
	for _, output := range response.Stacks[0].Outputs {
		if aws.StringValue(output.OutputKey) == "AnalysisApiEndpoint" {
			endpoint = *output.OutputValue
			break
		}
	}
	require.NotEmpty(t, endpoint)

	// Reset data stores: S3 bucket and Dynamo table
	require.NoError(t, testutils.ClearS3Bucket(awsSession, bucketName))
	require.NoError(t, testutils.ClearDynamoTable(awsSession, tableName))

	apiClient = client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(endpoint))

	// ORDER MATTERS!

	t.Run("TestPolicies", func(t *testing.T) {
		t.Run("TestPolicyPass", testPolicyPass)
		t.Run("TestPolicyFail", testPolicyFail)
		t.Run("TestPolicyError", testPolicyError)
		t.Run("TestPolicyNotApplicable", testPolicyNotApplicable)
		t.Run("TestPolicyMixed", testPolicyMixed)
	})

	// These tests must be run before any data is input
	t.Run("TestEmpty", func(t *testing.T) {
		t.Run("GetEnabledEmpty", getEnabledEmpty)
		t.Run("ListNotFound", listNotFound)
	})

	t.Run("Create", func(t *testing.T) {
		t.Run("CreatePolicyInvalid", createInvalid)
		t.Run("CreatePolicySuccess", createPolicySuccess)
		t.Run("CreateRuleSuccess", createRuleSuccess)
		// This test (and the other global tests) does trigger the layer-manager lambda to run, but since there is only
		// support for a single global nothing changes (the version gets bumped a few times). Once multiple globals are
		// supported, these tests can be improved to run policies and rules that rely on these imports.
		t.Run("CreateGlobalSuccess", createGlobalSuccess)
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
		t.Run("ListSuccess", listSuccess)
		t.Run("ListFiltered", listFiltered)
		t.Run("ListPaging", listPaging)
		t.Run("ListRules", listRules)
		t.Run("GetEnabledPolicies", getEnabledPolicies)
		t.Run("GetEnabledRules", getEnabledRules)
	})

	t.Run("Modify", func(t *testing.T) {
		t.Run("ModifyInvalid", modifyInvalid)
		t.Run("ModifyNotFound", modifyNotFound)
		t.Run("ModifySuccess", modifySuccess)
		t.Run("ModifyRule", modifyRule)
		t.Run("ModifyGlobal", modifyGlobal)
	})

	t.Run("Suppress", func(t *testing.T) {
		t.Run("SuppressNotFound", suppressNotFound)
		t.Run("SuppressSuccess", suppressSuccess)
	})

	// TODO: Add integration tests for integrated pass/fail info
	// E.g. filter + sort policies with different failure counts

	t.Run("Delete", func(t *testing.T) {
		t.Run("DeleteInvalid", deleteInvalid)
		t.Run("DeleteNotExists", deleteNotExists)
		t.Run("DeleteSuccess", deleteSuccess)
		t.Run("DeleteGlobal", deleteGlobal)
	})
}

func testPolicyPass(t *testing.T) {
	result, err := apiClient.Operations.TestPolicy(&operations.TestPolicyParams{
		Body: &models.TestPolicy{
			AnalysisType:  models.AnalysisTypePOLICY,
			Body:          policy.Body,
			ResourceTypes: policy.ResourceTypes,
			Tests:         policy.Tests,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)
	expected := &models.TestPolicyResult{
		TestSummary:  true,
		TestsErrored: models.TestsErrored{},
		TestsFailed:  models.TestsFailed{},
		TestsPassed:  models.TestsPassed{string(policy.Tests[0].Name), string(policy.Tests[1].Name)},
	}
	assert.Equal(t, expected, result.Payload)
}

func testPolicyNotApplicable(t *testing.T) {
	result, err := apiClient.Operations.TestPolicy(&operations.TestPolicyParams{
		Body: &models.TestPolicy{
			AnalysisType:  models.AnalysisTypePOLICY,
			Body:          policy.Body,
			ResourceTypes: policy.ResourceTypes,
			Tests: models.TestSuite{
				{
					ExpectedResult: policy.Tests[0].ExpectedResult,
					Name:           policy.Tests[0].Name,
					Resource:       policy.Tests[0].Resource,
					ResourceType:   "Wrong Resource Type",
				},
			},
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)
	expected := &models.TestPolicyResult{
		TestSummary: false,
		TestsErrored: models.TestsErrored{
			{
				ErrorMessage: "test resource type Wrong Resource Type is not applicable to this policy",
				Name:         string(policy.Tests[0].Name),
			},
		},
		TestsFailed: models.TestsFailed{},
		TestsPassed: models.TestsPassed{},
	}
	assert.Equal(t, expected, result.Payload)
}

func testPolicyFail(t *testing.T) {
	result, err := apiClient.Operations.TestPolicy(&operations.TestPolicyParams{
		Body: &models.TestPolicy{
			AnalysisType:  models.AnalysisTypePOLICY,
			Body:          "def policy(resource): return False",
			ResourceTypes: policy.ResourceTypes,
			Tests:         policy.Tests,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)
	expected := &models.TestPolicyResult{
		TestSummary:  false,
		TestsErrored: models.TestsErrored{},
		TestsFailed:  models.TestsFailed{string(policy.Tests[0].Name), string(policy.Tests[1].Name)},
		TestsPassed:  models.TestsPassed{},
	}
	assert.Equal(t, expected, result.Payload)
}

func testPolicyError(t *testing.T) {
	result, err := apiClient.Operations.TestPolicy(&operations.TestPolicyParams{
		Body: &models.TestPolicy{
			AnalysisType:  models.AnalysisTypePOLICY,
			Body:          "whatever, I do what I want",
			ResourceTypes: policy.ResourceTypes,
			Tests:         policy.Tests,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)
	expected := &models.TestPolicyResult{
		TestSummary: false,
		TestsErrored: models.TestsErrored{
			{
				ErrorMessage: "SyntaxError: invalid syntax (PolicyApiTestingPolicy.py, line 1)",
				Name:         string(policy.Tests[0].Name),
			},
			{
				ErrorMessage: "SyntaxError: invalid syntax (PolicyApiTestingPolicy.py, line 1)",
				Name:         string(policy.Tests[1].Name),
			},
		},
		TestsFailed: models.TestsFailed{},
		TestsPassed: models.TestsPassed{},
	}
	assert.Equal(t, expected, result.Payload)
}

func testPolicyMixed(t *testing.T) {
	result, err := apiClient.Operations.TestPolicy(&operations.TestPolicyParams{
		Body: &models.TestPolicy{
			AnalysisType:  models.AnalysisTypePOLICY,
			Body:          "def policy(resource): return resource['Hello']",
			ResourceTypes: policy.ResourceTypes,
			Tests: models.TestSuite{
				{
					ExpectedResult: true,
					Name:           "test-1",
					Resource:       `{"Hello": true}`,
					ResourceType:   "AWS.S3.Bucket",
				},
				{
					ExpectedResult: false,
					Name:           "test-2",
					Resource:       `{"Hello": false}`,
					ResourceType:   "AWS.S3.Bucket",
				},
				{
					ExpectedResult: true,
					Name:           "test-3",
					Resource:       `{"Hello": false}`,
					ResourceType:   "AWS.S3.Bucket",
				},
				{
					ExpectedResult: true,
					Name:           "test-4",
					Resource:       `{"Goodbye": false}`,
					ResourceType:   "AWS.S3.Bucket",
				},
			},
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)
	expected := &models.TestPolicyResult{
		TestSummary: false,
		TestsErrored: models.TestsErrored{
			{
				ErrorMessage: "KeyError: 'Hello'",
				Name:         "test-4",
			},
		},
		TestsFailed: models.TestsFailed{"test-3"},
		TestsPassed: models.TestsPassed{"test-1", "test-2"},
	}
	assert.Equal(t, expected, result.Payload)
}

func createInvalid(t *testing.T) {
	result, err := apiClient.Operations.CreatePolicy(&operations.CreatePolicyParams{HTTPClient: httpClient})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.CreatePolicyBadRequest{}, err)
}

func createPolicySuccess(t *testing.T) {
	result, err := apiClient.Operations.CreatePolicy(&operations.CreatePolicyParams{
		Body: &models.UpdatePolicy{
			AutoRemediationID:         policy.AutoRemediationID,
			AutoRemediationParameters: policy.AutoRemediationParameters,
			Body:                      policy.Body,
			Description:               policy.Description,
			DisplayName:               policy.DisplayName,
			Enabled:                   policy.Enabled,
			ID:                        policy.ID,
			ResourceTypes:             policy.ResourceTypes,
			Severity:                  policy.Severity,
			Suppressions:              policy.Suppressions,
			Tags:                      policy.Tags,
			UserID:                    userID,
			Tests:                     policy.Tests,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)

	require.NoError(t, result.Payload.Validate(nil))
	assert.NotZero(t, result.Payload.CreatedAt)
	assert.NotZero(t, result.Payload.LastModified)

	expectedPolicy := *policy
	expectedPolicy.CreatedAt = result.Payload.CreatedAt
	expectedPolicy.CreatedBy = userID
	expectedPolicy.LastModified = result.Payload.LastModified
	expectedPolicy.LastModifiedBy = userID
	expectedPolicy.VersionID = result.Payload.VersionID
	assert.Equal(t, &expectedPolicy, result.Payload)
}

func createRuleSuccess(t *testing.T) {
	result, err := apiClient.Operations.CreateRule(&operations.CreateRuleParams{
		Body: &models.UpdateRule{
			Body:               rule.Body,
			Description:        rule.Description,
			Enabled:            rule.Enabled,
			ID:                 rule.ID,
			LogTypes:           rule.LogTypes,
			Severity:           rule.Severity,
			UserID:             userID,
			DedupPeriodMinutes: rule.DedupPeriodMinutes,
			Tags:               rule.Tags,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)

	require.NoError(t, result.Payload.Validate(nil))
	assert.NotZero(t, result.Payload.CreatedAt)
	assert.NotZero(t, result.Payload.LastModified)

	expectedRule := *rule
	expectedRule.CreatedAt = result.Payload.CreatedAt
	expectedRule.CreatedBy = userID
	expectedRule.LastModified = result.Payload.LastModified
	expectedRule.LastModifiedBy = userID
	expectedRule.VersionID = result.Payload.VersionID
	assert.Equal(t, &expectedRule, result.Payload)
}

func createGlobalSuccess(t *testing.T) {
	result, err := apiClient.Operations.CreateGlobal(&operations.CreateGlobalParams{
		Body: &models.UpdateGlobal{
			Body:        global.Body,
			Description: global.Description,
			ID:          global.ID,
			UserID:      userID,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)

	require.NoError(t, result.Payload.Validate(nil))
	assert.NotZero(t, result.Payload.CreatedAt)
	assert.NotZero(t, result.Payload.LastModified)

	global.CreatedAt = result.Payload.CreatedAt
	global.CreatedBy = userID
	global.LastModified = result.Payload.LastModified
	global.LastModifiedBy = userID
	global.Tags = []string{} // nil was converted to empty list
	global.VersionID = result.Payload.VersionID
	assert.Equal(t, global, result.Payload)
}

func getNotFound(t *testing.T) {
	result, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   "does-not-exist",
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.GetPolicyNotFound{}, err)
}

// Get the latest policy version (from Dynamo)
func getLatest(t *testing.T) {
	result, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policy.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.NoError(t, result.Payload.Validate(nil))

	// set things that change
	expectedPolicy := *policy
	expectedPolicy.CreatedAt = result.Payload.CreatedAt
	expectedPolicy.CreatedBy = userID
	expectedPolicy.LastModified = result.Payload.LastModified
	expectedPolicy.LastModifiedBy = userID
	expectedPolicy.VersionID = result.Payload.VersionID
	assert.Equal(t, &expectedPolicy, result.Payload)
}

// Get a specific policy version (from S3)
func getVersion(t *testing.T) {
	// first get the version now as latest
	result, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policy.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.NoError(t, result.Payload.Validate(nil))

	versionedPolicy = result.Payload // remember for later in delete tests, since it will change

	// set version we expect
	expectedPolicy := *policy
	expectedPolicy.VersionID = result.Payload.VersionID

	// now look it up
	result, err = apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policy.ID),
		VersionID:  aws.String(string(result.Payload.VersionID)),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.NoError(t, result.Payload.Validate(nil))

	// set things that change but NOT the version
	expectedPolicy.CreatedAt = result.Payload.CreatedAt
	expectedPolicy.CreatedBy = userID
	expectedPolicy.LastModified = result.Payload.LastModified
	expectedPolicy.LastModifiedBy = userID
	assert.Equal(t, &expectedPolicy, result.Payload)
}

// Get a rule
func getRule(t *testing.T) {
	result, err := apiClient.Operations.GetRule(&operations.GetRuleParams{
		RuleID:     string(rule.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.NoError(t, result.Payload.Validate(nil))
	expectedRule := *rule
	// these get assigned
	expectedRule.CreatedBy = result.Payload.CreatedBy
	expectedRule.LastModifiedBy = result.Payload.LastModifiedBy
	expectedRule.CreatedAt = result.Payload.CreatedAt
	expectedRule.LastModified = result.Payload.LastModified
	expectedRule.VersionID = result.Payload.VersionID
	assert.Equal(t, &expectedRule, result.Payload)
}

// Get a global
func getGlobal(t *testing.T) {
	result, err := apiClient.Operations.GetGlobal(&operations.GetGlobalParams{
		GlobalID:   string(global.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.NoError(t, result.Payload.Validate(nil))
	assert.Equal(t, global, result.Payload)
}

// GetRule with a policy ID returns 404 not found
func getRuleWrongType(t *testing.T) {
	result, err := apiClient.Operations.GetRule(&operations.GetRuleParams{
		RuleID:     string(policy.ID),
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.GetRuleNotFound{}, err)
}

func modifyInvalid(t *testing.T) {
	result, err := apiClient.Operations.ModifyPolicy(&operations.ModifyPolicyParams{
		// missing fields
		Body:       &models.UpdatePolicy{},
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.ModifyPolicyBadRequest{}, err)
}

func modifyNotFound(t *testing.T) {
	result, err := apiClient.Operations.ModifyPolicy(&operations.ModifyPolicyParams{
		Body: &models.UpdatePolicy{
			Body:     "def policy(resource): return False",
			Enabled:  policy.Enabled,
			ID:       "DOES.NOT.EXIST",
			Severity: policy.Severity,
			UserID:   userID,
		},
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.ModifyPolicyNotFound{}, err)
}

func modifySuccess(t *testing.T) {
	// things we will change
	expectedPolicy := *policy
	expectedPolicy.Description = "A new and modified description!"
	expectedPolicy.Tests = []*models.UnitTest{
		{
			Name:           "This will be True",
			ResourceType:   "AWS.S3.Bucket",
			ExpectedResult: true,
			Resource:       `{}`,
		},
	}
	result, err := apiClient.Operations.ModifyPolicy(&operations.ModifyPolicyParams{
		Body: &models.UpdatePolicy{
			AutoRemediationID:         policy.AutoRemediationID,
			AutoRemediationParameters: policy.AutoRemediationParameters,
			Body:                      policy.Body,
			Description:               expectedPolicy.Description,
			DisplayName:               policy.DisplayName,
			Enabled:                   policy.Enabled,
			ID:                        policy.ID,
			ResourceTypes:             policy.ResourceTypes,
			Severity:                  policy.Severity,
			Suppressions:              policy.Suppressions,
			Tags:                      policy.Tags,
			Tests:                     expectedPolicy.Tests,
			UserID:                    userID,
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	// these get assigned
	expectedPolicy.CreatedBy = result.Payload.CreatedBy
	expectedPolicy.LastModifiedBy = result.Payload.LastModifiedBy
	expectedPolicy.CreatedAt = result.Payload.CreatedAt
	expectedPolicy.LastModified = result.Payload.LastModified
	expectedPolicy.VersionID = result.Payload.VersionID
	assert.Equal(t, &expectedPolicy, result.Payload)
}

// Modify a rule
func modifyRule(t *testing.T) {
	// these are changes
	expectedRule := *rule
	expectedRule.Description = "SkyNet integration"
	expectedRule.DedupPeriodMinutes = 60

	result, err := apiClient.Operations.ModifyRule(&operations.ModifyRuleParams{
		Body: &models.UpdateRule{
			Body:               expectedRule.Body,
			Description:        expectedRule.Description,
			Enabled:            expectedRule.Enabled,
			ID:                 expectedRule.ID,
			LogTypes:           expectedRule.LogTypes,
			Severity:           expectedRule.Severity,
			UserID:             userID,
			DedupPeriodMinutes: expectedRule.DedupPeriodMinutes,
			Tags:               expectedRule.Tags,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)

	require.NoError(t, result.Payload.Validate(nil))
	assert.NotZero(t, result.Payload.CreatedAt)
	assert.NotZero(t, result.Payload.LastModified)

	expectedRule.CreatedBy = result.Payload.CreatedBy
	expectedRule.LastModifiedBy = result.Payload.LastModifiedBy
	expectedRule.CreatedAt = result.Payload.CreatedAt
	expectedRule.LastModified = result.Payload.LastModified
	expectedRule.VersionID = result.Payload.VersionID
	assert.Equal(t, &expectedRule, result.Payload)
}

// Modify a global
func modifyGlobal(t *testing.T) {
	global.Description = "Now returns False"
	global.Body = "def helper_is_true(truthy): return truthy is False\n"

	result, err := apiClient.Operations.ModifyGlobal(&operations.ModifyGlobalParams{
		Body: &models.UpdateGlobal{
			Body:        global.Body,
			Description: global.Description,
			ID:          global.ID,
			UserID:      userID,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)

	require.NoError(t, result.Payload.Validate(nil))
	assert.NotZero(t, result.Payload.CreatedAt)
	assert.NotZero(t, result.Payload.LastModified)

	global.LastModified = result.Payload.LastModified
	global.VersionID = result.Payload.VersionID
	assert.Equal(t, global, result.Payload)
}

func suppressNotFound(t *testing.T) {
	result, err := apiClient.Operations.Suppress(&operations.SuppressParams{
		Body: &models.Suppress{
			PolicyIds:        []models.ID{"no-such-id"},
			ResourcePatterns: models.Suppressions{"s3:.*"},
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	// a policy which doesn't exist logs a warning but doesn't return an API error
	assert.Equal(t, &operations.SuppressOK{}, result)
}

func suppressSuccess(t *testing.T) {
	result, err := apiClient.Operations.Suppress(&operations.SuppressParams{
		Body: &models.Suppress{
			PolicyIds:        []models.ID{policy.ID},
			ResourcePatterns: models.Suppressions{"new-suppression"},
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.SuppressOK{}, result)

	// Verify suppressions were added correctly
	getResult, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policy.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	sort.Strings(getResult.Payload.Suppressions)
	// It was added to the existing suppressions
	assert.Equal(t, models.Suppressions{"new-suppression", "panther.*"}, getResult.Payload.Suppressions)
}

func bulkUploadInvalid(t *testing.T) {
	result, err := apiClient.Operations.BulkUpload(
		&operations.BulkUploadParams{HTTPClient: httpClient})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.BulkUploadBadRequest{}, err)
}

func bulkUploadSuccess(t *testing.T) {
	require.NoError(t, shutil.ZipDirectory(policiesRoot, policiesZipLocation, true))
	zipFile, err := os.Open(policiesZipLocation)
	require.NoError(t, err)
	content, err := ioutil.ReadAll(bufio.NewReader(zipFile))
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(content)
	result, err := apiClient.Operations.BulkUpload(&operations.BulkUploadParams{
		Body: &models.BulkUpload{
			Data:   models.Base64zipfile(encoded),
			UserID: userID,
		},
		HTTPClient: httpClient,
	})

	require.NoError(t, err)

	expected := &models.BulkUploadResult{
		ModifiedPolicies: aws.Int64(1),
		NewPolicies:      aws.Int64(2),
		TotalPolicies:    aws.Int64(3),

		ModifiedRules: aws.Int64(0),
		NewRules:      aws.Int64(0),
		TotalRules:    aws.Int64(0),

		ModifiedGlobals: aws.Int64(0),
		NewGlobals:      aws.Int64(0),
		TotalGlobals:    aws.Int64(0),
	}
	assert.Equal(t, expected, result.Payload)

	// Verify the existing policy was updated - the created fields were unchanged
	getResult, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policy.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	assert.NoError(t, getResult.Payload.Validate(nil))
	assert.True(t, time.Time(getResult.Payload.LastModified).After(time.Time(policy.LastModified)))
	assert.NotEqual(t, getResult.Payload.VersionID, policy.VersionID)
	assert.NotEmpty(t, getResult.Payload.VersionID)

	expectedPolicy := *policy
	expectedPolicy.AutoRemediationParameters = map[string]string{"hello": "goodbye"}
	expectedPolicy.Description = "Matches every resource\n"
	expectedPolicy.CreatedBy = getResult.Payload.CreatedBy
	expectedPolicy.LastModifiedBy = getResult.Payload.LastModifiedBy
	expectedPolicy.CreatedAt = getResult.Payload.CreatedAt
	expectedPolicy.LastModified = getResult.Payload.LastModified
	expectedPolicy.Tests = expectedPolicy.Tests[:1]
	expectedPolicy.Tests[0].Resource = `{"Bucket":"empty"}`
	expectedPolicy.Tags = []string{}
	expectedPolicy.VersionID = getResult.Payload.VersionID
	assert.Equal(t, &expectedPolicy, getResult.Payload)

	// Now reset global policy so subsequent tests have a reference
	policy = getResult.Payload

	// Verify newly created policy #1
	getResult, err = apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policyFromBulk.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	assert.NoError(t, getResult.Payload.Validate(nil))
	assert.NotZero(t, getResult.Payload.CreatedAt)
	assert.NotZero(t, getResult.Payload.LastModified)
	policyFromBulk.CreatedAt = getResult.Payload.CreatedAt
	policyFromBulk.LastModified = getResult.Payload.LastModified
	policyFromBulk.Suppressions = []string{}
	policyFromBulk.VersionID = getResult.Payload.VersionID

	// Verify the resource string is the same as we expect, by unmarshalling it into its object map
	for i, test := range policyFromBulk.Tests {
		var expected map[string]interface{}
		var actual map[string]interface{}
		require.NoError(t, jsoniter.UnmarshalFromString(string(test.Resource), &expected))
		require.NoError(t, jsoniter.UnmarshalFromString(string(getResult.Payload.Tests[i].Resource), &actual))
		assert.Equal(t, expected, actual)
		test.Resource = getResult.Payload.Tests[i].Resource
	}

	assert.Equal(t, policyFromBulk, getResult.Payload)

	// Verify newly created policy #2
	getResult, err = apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policyFromBulkJSON.ID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	assert.NoError(t, getResult.Payload.Validate(nil))
	assert.NotZero(t, getResult.Payload.CreatedAt)
	assert.NotZero(t, getResult.Payload.LastModified)
	policyFromBulkJSON.CreatedAt = getResult.Payload.CreatedAt
	policyFromBulkJSON.LastModified = getResult.Payload.LastModified
	policyFromBulkJSON.Tags = []string{}
	policyFromBulkJSON.VersionID = getResult.Payload.VersionID

	// Verify the resource string is the same as we expect, by unmarshaling it into its object map
	for i, test := range policyFromBulkJSON.Tests {
		var expected map[string]interface{}
		var actual map[string]interface{}
		require.NoError(t, jsoniter.UnmarshalFromString(string(test.Resource), &expected))
		require.NoError(t, jsoniter.UnmarshalFromString(string(getResult.Payload.Tests[i].Resource), &actual))
		assert.Equal(t, expected, actual)
		test.Resource = getResult.Payload.Tests[i].Resource
	}

	assert.Equal(t, policyFromBulkJSON, getResult.Payload)
}

func listNotFound(t *testing.T) {
	result, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(0),
			TotalItems: aws.Int64(0),
			TotalPages: aws.Int64(0),
		},
		Policies: []*models.PolicySummary{},
	}
	assert.Equal(t, expected, result.Payload)
}

func listSuccess(t *testing.T) {
	result, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		HTTPClient: httpClient,
		SortBy:     aws.String("id"),
	})
	require.NoError(t, err)

	expected := &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(1),
		},
		Policies: []*models.PolicySummary{ // sorted by id
			{
				AutoRemediationID:         policyFromBulkJSON.AutoRemediationID,
				AutoRemediationParameters: policyFromBulkJSON.AutoRemediationParameters,
				ComplianceStatus:          models.ComplianceStatusPASS,
				DisplayName:               policyFromBulkJSON.DisplayName,
				Enabled:                   policyFromBulkJSON.Enabled,
				ID:                        policyFromBulkJSON.ID,
				LastModified:              policyFromBulkJSON.LastModified,
				ResourceTypes:             policyFromBulkJSON.ResourceTypes,
				Severity:                  policyFromBulkJSON.Severity,
				Suppressions:              policyFromBulkJSON.Suppressions,
				Tags:                      []string{},
				Reports:                   map[string][]string{},
			},
			{
				AutoRemediationID:         policy.AutoRemediationID,
				AutoRemediationParameters: policy.AutoRemediationParameters,
				ComplianceStatus:          models.ComplianceStatusPASS,
				DisplayName:               policy.DisplayName,
				Enabled:                   policy.Enabled,
				ID:                        policy.ID,
				LastModified:              result.Payload.Policies[1].LastModified, // this gets set
				ResourceTypes:             policy.ResourceTypes,
				Severity:                  policy.Severity,
				Suppressions:              policy.Suppressions,
				Tags:                      []string{},
				Reports:                   map[string][]string{},
			},
			{
				AutoRemediationID:         policyFromBulk.AutoRemediationID,
				AutoRemediationParameters: policyFromBulk.AutoRemediationParameters,
				ComplianceStatus:          models.ComplianceStatusPASS,
				DisplayName:               policyFromBulk.DisplayName,
				Enabled:                   policyFromBulk.Enabled,
				ID:                        policyFromBulk.ID,
				LastModified:              policyFromBulk.LastModified,
				ResourceTypes:             policyFromBulk.ResourceTypes,
				Severity:                  policyFromBulk.Severity,
				Suppressions:              policyFromBulk.Suppressions,
				Tags:                      policyFromBulk.Tags,
				Reports:                   map[string][]string{},
			},
		},
	}

	require.Len(t, result.Payload.Policies, len(expected.Policies))
	assert.Equal(t, expected, result.Payload)
}

func listFiltered(t *testing.T) {
	result, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		Enabled:        aws.Bool(true),
		HasRemediation: aws.Bool(true),
		NameContains:   aws.String("json"), // policyFromBulkJSON only
		ResourceTypes:  []string{"AWS.S3.Bucket"},
		Severity:       aws.String(string(models.SeverityMEDIUM)),
		HTTPClient:     httpClient,
	})
	require.NoError(t, err)

	expected := &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(1),
			TotalPages: aws.Int64(1),
		},
		Policies: []*models.PolicySummary{
			{
				AutoRemediationID:         policyFromBulkJSON.AutoRemediationID,
				AutoRemediationParameters: policyFromBulkJSON.AutoRemediationParameters,
				ComplianceStatus:          models.ComplianceStatusPASS,
				DisplayName:               policyFromBulkJSON.DisplayName,
				Enabled:                   policyFromBulkJSON.Enabled,
				ID:                        policyFromBulkJSON.ID,
				LastModified:              policyFromBulkJSON.LastModified,
				ResourceTypes:             policyFromBulkJSON.ResourceTypes,
				Severity:                  policyFromBulkJSON.Severity,
				Suppressions:              policyFromBulkJSON.Suppressions,
				Tags:                      policyFromBulkJSON.Tags,
				Reports:                   policyFromBulkJSON.Reports,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func listPaging(t *testing.T) {
	// Page 1
	result, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		PageSize:   aws.Int64(1),
		SortBy:     aws.String("id"),
		SortDir:    aws.String("descending"),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(3),
		},
		Policies: []*models.PolicySummary{
			{
				AutoRemediationID:         policyFromBulkJSON.AutoRemediationID,
				AutoRemediationParameters: policyFromBulkJSON.AutoRemediationParameters,
				ComplianceStatus:          models.ComplianceStatusPASS,
				DisplayName:               policyFromBulkJSON.DisplayName,
				Enabled:                   policyFromBulkJSON.Enabled,
				ID:                        policyFromBulkJSON.ID,
				LastModified:              policyFromBulkJSON.LastModified,
				ResourceTypes:             policyFromBulkJSON.ResourceTypes,
				Severity:                  policyFromBulkJSON.Severity,
				Suppressions:              policyFromBulkJSON.Suppressions,
				Tags:                      policyFromBulkJSON.Tags,
				Reports:                   policyFromBulkJSON.Reports,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)

	// Page 2
	result, err = apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		Page:       aws.Int64(2),
		PageSize:   aws.Int64(1),
		SortBy:     aws.String("id"),
		SortDir:    aws.String("descending"),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected = &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(2),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(3),
		},
		Policies: []*models.PolicySummary{
			{
				AutoRemediationID:         policy.AutoRemediationID,
				AutoRemediationParameters: policy.AutoRemediationParameters,
				ComplianceStatus:          models.ComplianceStatusPASS,
				DisplayName:               policy.DisplayName,
				Enabled:                   policy.Enabled,
				ID:                        policy.ID,
				LastModified:              result.Payload.Policies[0].LastModified, // this gets set
				ResourceTypes:             policy.ResourceTypes,
				Severity:                  policy.Severity,
				Suppressions:              policy.Suppressions,
				Tags:                      policy.Tags,
				Reports:                   policy.Reports,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)

	// Page 3
	result, err = apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		Page:       aws.Int64(3),
		PageSize:   aws.Int64(1),
		SortBy:     aws.String("id"),
		SortDir:    aws.String("descending"),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected = &models.PolicyList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(3),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(3),
		},
		Policies: []*models.PolicySummary{
			{
				AutoRemediationID:         policyFromBulk.AutoRemediationID,
				AutoRemediationParameters: policyFromBulk.AutoRemediationParameters,
				ComplianceStatus:          models.ComplianceStatusPASS,
				DisplayName:               policyFromBulk.DisplayName,
				Enabled:                   policyFromBulk.Enabled,
				ID:                        policyFromBulk.ID,
				LastModified:              policyFromBulk.LastModified,
				ResourceTypes:             policyFromBulk.ResourceTypes,
				Severity:                  policyFromBulk.Severity,
				Suppressions:              policyFromBulk.Suppressions,
				Tags:                      policyFromBulk.Tags,
				Reports:                   policyFromBulk.Reports,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

// List rules (not policies)
func listRules(t *testing.T) {
	result, err := apiClient.Operations.ListRules(&operations.ListRulesParams{
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.RuleList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(1),
			TotalPages: aws.Int64(1),
		},
		Rules: []*models.RuleSummary{
			{
				DisplayName:  rule.DisplayName,
				Enabled:      rule.Enabled,
				ID:           rule.ID,
				LastModified: result.Payload.Rules[0].LastModified, // this is changed
				LogTypes:     rule.LogTypes,
				Severity:     rule.Severity,
				Tags:         rule.Tags,
				Reports:      rule.Reports,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func getEnabledEmpty(t *testing.T) {
	result, err := apiClient.Operations.GetEnabledPolicies(&operations.GetEnabledPoliciesParams{
		HTTPClient: httpClient,
		Type:       string(models.AnalysisTypePOLICY),
	})
	require.NoError(t, err)
	assert.Equal(t, &models.EnabledPolicies{Policies: []*models.EnabledPolicy{}}, result.Payload)
}

func getEnabledPolicies(t *testing.T) {
	result, err := apiClient.Operations.GetEnabledPolicies(&operations.GetEnabledPoliciesParams{
		HTTPClient: httpClient,
		Type:       string(models.AnalysisTypePOLICY),
	})
	require.NoError(t, err)

	// use map, do not count on order
	expected := map[models.ID]*models.EnabledPolicy{
		policy.ID: {
			Body:          policy.Body,
			ID:            policy.ID,
			ResourceTypes: policy.ResourceTypes,
			Severity:      policy.Severity,
			VersionID:     result.Payload.Policies[0].VersionID, // this is set
			Suppressions:  policy.Suppressions,
		},
		policyFromBulkJSON.ID: {
			Body:          policyFromBulkJSON.Body,
			ID:            policyFromBulkJSON.ID,
			ResourceTypes: policyFromBulkJSON.ResourceTypes,
			Severity:      policyFromBulkJSON.Severity,
			VersionID:     policyFromBulkJSON.VersionID,
			Reports: map[string][]string{
				"Test": {"Value1", "Value2"},
			},
		},
		policyFromBulk.ID: {
			Body:          policyFromBulk.Body,
			ID:            policyFromBulk.ID,
			ResourceTypes: policyFromBulk.ResourceTypes,
			Severity:      policyFromBulk.Severity,
			VersionID:     policyFromBulk.VersionID,
			Tags:          policyFromBulk.Tags,
		},
	}

	for _, resultPolicy := range result.Payload.Policies {
		assert.Equal(t, expected[resultPolicy.ID], resultPolicy)
	}
}

// Get enabled rules (instead of policies)
func getEnabledRules(t *testing.T) {
	result, err := apiClient.Operations.GetEnabledPolicies(&operations.GetEnabledPoliciesParams{
		Type:       string(models.AnalysisTypeRULE),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.EnabledPolicies{
		Policies: []*models.EnabledPolicy{
			{
				Body:               rule.Body,
				ID:                 rule.ID,
				ResourceTypes:      rule.LogTypes,
				Severity:           rule.Severity,
				VersionID:          result.Payload.Policies[0].VersionID, // this is set
				DedupPeriodMinutes: rule.DedupPeriodMinutes,
				Tags:               rule.Tags,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func deleteInvalid(t *testing.T) {
	result, err := apiClient.Operations.DeletePolicies(&operations.DeletePoliciesParams{
		Body:       &models.DeletePolicies{},
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.DeletePoliciesBadRequest{}, err)
}

// Delete a set of policies that don't exist - returns OK
func deleteNotExists(t *testing.T) {
	result, err := apiClient.Operations.DeletePolicies(&operations.DeletePoliciesParams{
		Body: &models.DeletePolicies{
			Policies: []*models.DeleteEntry{
				{
					ID: "does-not-exist",
				},
				{
					ID: "also-does-not-exist",
				},
			},
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.DeletePoliciesOK{}, result)
}

func deleteSuccess(t *testing.T) {
	result, err := apiClient.Operations.DeletePolicies(&operations.DeletePoliciesParams{
		Body: &models.DeletePolicies{
			Policies: []*models.DeleteEntry{
				{
					ID: policy.ID,
				},
				{
					ID: policyFromBulk.ID,
				},
				{
					ID: policyFromBulkJSON.ID,
				},
				{
					ID: rule.ID,
				},
			},
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.DeletePoliciesOK{}, result)

	// Trying to retrieve the deleted policy should now return 404
	_, err = apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(policy.ID),
		HTTPClient: httpClient,
	})
	require.Error(t, err)
	require.IsType(t, &operations.GetPolicyNotFound{}, err)

	// But retrieving an older version will still work...
	getResult, err := apiClient.Operations.GetPolicy(&operations.GetPolicyParams{
		PolicyID:   string(versionedPolicy.ID),
		VersionID:  aws.String(string(versionedPolicy.VersionID)),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	assert.Equal(t, versionedPolicy, getResult.Payload)

	// List operations should be empty
	emptyPaging := &models.Paging{
		ThisPage:   aws.Int64(0),
		TotalItems: aws.Int64(0),
		TotalPages: aws.Int64(0),
	}

	policyList, err := apiClient.Operations.ListPolicies(&operations.ListPoliciesParams{
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	expectedPolicyList := &models.PolicyList{Paging: emptyPaging, Policies: []*models.PolicySummary{}}
	assert.Equal(t, expectedPolicyList, policyList.Payload)

	ruleList, err := apiClient.Operations.ListRules(&operations.ListRulesParams{
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	expectedRuleList := &models.RuleList{Paging: emptyPaging, Rules: []*models.RuleSummary{}}
	assert.Equal(t, expectedRuleList, ruleList.Payload)
}

func deleteGlobal(t *testing.T) {
	result, err := apiClient.Operations.DeleteGlobals(&operations.DeleteGlobalsParams{
		Body: &models.DeletePolicies{
			Policies: []*models.DeleteEntry{
				{
					ID: global.ID,
				},
			},
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.DeleteGlobalsOK{}, result)

	// Trying to retrieve the deleted policy should now return 404
	_, err = apiClient.Operations.GetGlobal(&operations.GetGlobalParams{
		GlobalID:   string(global.ID),
		HTTPClient: httpClient,
	})
	require.Error(t, err)
	require.IsType(t, &operations.GetGlobalNotFound{}, err)

	// But retrieving an older version will still work
	getResult, err := apiClient.Operations.GetGlobal(&operations.GetGlobalParams{
		GlobalID:   string(global.ID),
		VersionID:  aws.String(string(global.VersionID)),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, global, getResult.Payload)
}
