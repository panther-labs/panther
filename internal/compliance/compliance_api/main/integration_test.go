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
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	apiClient       = gatewayapi.NewClient(lambda.New(awsSession), "panther-compliance-api")
	integrationID   = "f0e95b8b-6d93-4de5-a963-a2974fd2ba72"

	// 5 policies: 1 error, 2 fail (1 suppressed), 2 pass across 3 resources and 4 policies
	statuses = []models.ComplianceEntry{
		{
			ErrorMessage:   "ZeroDivisionError",
			PolicyID:       "AWS-S3-EncryptionEnabled",
			PolicySeverity: models.SeverityHigh,
			ResourceID:     "arn:aws:s3:::my-bucket",
			ResourceType:   "AWS.S3.Bucket",
			Status:         models.StatusError,
			Suppressed:     false,
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       "AWS-S3-Versioning",
			PolicySeverity: models.SeverityMedium,
			ResourceID:     "arn:aws:s3:::my-bucket",
			ResourceType:   "AWS.S3.Bucket",
			Status:         models.StatusFail,
			Suppressed:     true,
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       "AWS-S3-Versioning",
			PolicySeverity: models.SeverityMedium,
			ResourceID:     "arn:aws:s3:::my-other-bucket",
			ResourceType:   "AWS.S3.Bucket",
			Status:         models.StatusFail,
			Suppressed:     false,
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       "AWS-S3-BlockPublicAccess",
			PolicySeverity: models.SeverityCritical,
			ResourceID:     "arn:aws:s3:::my-bucket",
			ResourceType:   "AWS.S3.Bucket",
			Status:         models.StatusPass,
			Suppressed:     false,
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       "AWS-Cloudtrail-Encryption",
			PolicySeverity: models.SeverityCritical,
			ResourceID:     "arn:aws:cloudtrail:123412341234::my-trail",
			ResourceType:   "AWS.CloudTrail",
			Status:         models.StatusPass,
			Suppressed:     false,
			IntegrationID:  integrationID,
		},
	}
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

	// Reset Dynamo table
	require.NoError(t, testutils.ClearDynamoTable(awsSession, "panther-compliance"))

	t.Run("CheckEmpty", func(t *testing.T) {
		t.Run("DescribeOrgEmpty", describeOrgEmpty)
		t.Run("GetOrgOverviewEmpty", getOrgOverviewEmpty)
	})

	t.Run("SetStatus", func(t *testing.T) {
		t.Run("SetEmpty", setEmpty)
		t.Run("SetSuccess", setSuccess)
	})
	if t.Failed() {
		return
	}

	t.Run("GetStatus", func(t *testing.T) {
		t.Run("GetNotFound", getNotFound)
		t.Run("GetSuccess", getSuccess)
	})

	t.Run("DescribeOrg", func(t *testing.T) {
		t.Run("DescribeOrgPolicy", describeOrgPolicy)
		t.Run("DescribeOrgResource", describeOrgResource)
	})

	t.Run("DescribePolicy", func(t *testing.T) {
		t.Run("DescribePolicyEmpty", describePolicyEmpty)
		t.Run("DescribePolicy", describePolicy)
	})

	t.Run("DescribeResource", func(t *testing.T) {
		t.Run("DescribeResourceEmpty", describeResourceEmpty)
		t.Run("DescribeResource", describeResource)
	})

	t.Run("GetOrgOverview", func(t *testing.T) {
		t.Run("GetOrgOverview", getOrgOverview)
		t.Run("GetOrgOverviewCustomLimit", getOrgOverviewCustomLimit)
	})
	t.Run("DescribePolicyPageAndFilter", describePolicyPageAndFilter)

	t.Run("Update", update)
	t.Run("Delete", deleteBatch)
}

func setEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		SetStatus: &models.SetStatusInput{Entries: []models.SetStatusEntry{}},
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)
	assert.Equal(t, "panther-compliance-api: InvalidInputError: "+
		"Entries invalid, failed to satisfy the condition: min=1", err.Error())
}

func setSuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		SetStatus: &models.SetStatusInput{Entries: make([]models.SetStatusEntry, len(statuses))},
	}
	for i, status := range statuses {
		input.SetStatus.Entries[i] = models.SetStatusEntry{
			ErrorMessage:   status.ErrorMessage,
			PolicyID:       status.PolicyID,
			PolicySeverity: status.PolicySeverity,
			ResourceID:     status.ResourceID,
			ResourceType:   status.ResourceType,
			Status:         status.Status,
			Suppressed:     status.Suppressed,
			IntegrationID:  status.IntegrationID,
		}
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, statusCode)
}

func getNotFound(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetStatus: &models.GetStatusInput{
			PolicyID:   "no-such-policy",
			ResourceID: statuses[0].ResourceID,
		},
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

func getSuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetStatus: &models.GetStatusInput{
			PolicyID:   statuses[0].PolicyID,
			ResourceID: statuses[0].ResourceID,
		},
	}

	var result models.ComplianceEntry
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	for i := 0; i < len(statuses); i++ {
		assert.NotEmpty(t, result.ExpiresAt)
		statuses[i].ExpiresAt = result.ExpiresAt
		assert.NotEmpty(t, result.LastUpdated)
		statuses[i].LastUpdated = result.LastUpdated
	}
	assert.Equal(t, statuses[0], result)
}

func describeOrgEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DescribeOrg: &models.DescribeOrgInput{Type: "policy"},
	}

	var result models.DescribeOrgOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, models.DescribeOrgOutput{
		Resources: []models.ItemSummary{}, Policies: []models.ItemSummary{}}, result)
}

func describeOrgPolicy(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DescribeOrg: &models.DescribeOrgInput{Type: "policy"},
	}

	var result models.DescribeOrgOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.DescribeOrgOutput{
		Policies: []models.ItemSummary{
			{
				ID:     "AWS-S3-EncryptionEnabled", // 1 HIGH error
				Status: models.StatusError,
			},
			{
				ID:     "AWS-S3-Versioning", // 1 MEDIUM failure
				Status: models.StatusFail,
			},
			// passing policies are sorted by ID
			{
				ID:     "AWS-Cloudtrail-Encryption",
				Status: models.StatusPass,
			},
			{
				ID:     "AWS-S3-BlockPublicAccess",
				Status: models.StatusPass,
			},
		},
		Resources: []models.ItemSummary{},
	}
	assert.Equal(t, expected, result)
}

func describeOrgResource(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DescribeOrg: &models.DescribeOrgInput{Type: "resource"},
	}

	var result models.DescribeOrgOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.DescribeOrgOutput{
		Policies: []models.ItemSummary{},
		Resources: []models.ItemSummary{
			{
				ID:     "arn:aws:s3:::my-bucket", // 1 HIGH error
				Status: models.StatusError,
			},
			{
				ID:     "arn:aws:s3:::my-other-bucket", // 1 MEDIUM failure
				Status: models.StatusFail,
			},
			{
				ID:     "arn:aws:cloudtrail:123412341234::my-trail",
				Status: models.StatusPass,
			},
		},
	}
	assert.Equal(t, expected, result)
}

// A policy which doesn't exist returns empty results.
//
// We don't return 404 because a disabled policy will not exist in the compliance-api but would
// in the analysis-api
func describePolicyEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DescribePolicy: &models.DescribePolicyInput{PolicyID: "no-such-policy"},
	}

	var result models.PolicyResourceDetail
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.PolicyResourceDetail{
		Items:  []models.ComplianceEntry{},
		Status: models.StatusPass,
	}
	assert.Equal(t, expected, result)
}

func describePolicy(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DescribePolicy: &models.DescribePolicyInput{PolicyID: "AWS-Cloudtrail-Encryption"},
	}

	var result models.PolicyResourceDetail
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.PolicyResourceDetail{
		Items: []models.ComplianceEntry{
			statuses[4],
		},
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 1,
			TotalPages: 1,
		},
		Status: models.StatusPass,
		Totals: models.ActiveSuppressCount{
			Active: models.StatusCount{
				Pass: 1,
			},
		},
	}
	assert.Equal(t, expected, result)

	// Query a policy with 2 entries, one of which is suppressed
	input = models.LambdaInput{
		DescribePolicy: &models.DescribePolicyInput{PolicyID: "AWS-S3-Versioning"},
	}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected = models.PolicyResourceDetail{
		Items: []models.ComplianceEntry{
			statuses[2],
			statuses[1],
		},
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 2,
			TotalPages: 1,
		},
		Status: models.StatusFail,
		Totals: models.ActiveSuppressCount{
			Active: models.StatusCount{
				Fail: 1,
			},
			Suppressed: models.StatusCount{
				Fail: 1,
			},
		},
	}
	assert.Equal(t, expected, result)
}

// Test paging + filtering with more items
func describePolicyPageAndFilter(t *testing.T) {
	t.Parallel()

	// Add 18 entries with 3 copies of each (status, suppressed) combination
	entries := make([]models.SetStatusEntry, 18)
	integrationID := "52346bf0-e490-480b-a4b5-35fe83c98c17"
	policyID := "copy-policy"

	for i := 0; i < len(entries); i++ {
		var status models.ComplianceStatus
		switch {
		case i < 6:
			status = models.StatusError
		case i < 12:
			status = models.StatusFail
		default:
			status = models.StatusPass
		}

		suppressed := false
		if i%2 == 0 {
			suppressed = true
		}

		entries[i] = models.SetStatusEntry{
			PolicyID:       policyID,
			PolicySeverity: models.SeverityLow,
			ResourceID:     fmt.Sprintf("resource-%d", i),
			ResourceType:   "AWS.S3.Bucket",
			Status:         status,
			Suppressed:     suppressed,
			IntegrationID:  integrationID,
		}
	}

	input := models.LambdaInput{
		SetStatus: &models.SetStatusInput{Entries: entries},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, statusCode)

	// Fetch suppressed FAIL entries with pageSize=1
	input = models.LambdaInput{
		DescribePolicy: &models.DescribePolicyInput{
			PolicyID:   policyID,
			PageSize:   1,
			Status:     models.StatusFail,
			Suppressed: aws.Bool(true),
		},
	}
	var result models.PolicyResourceDetail
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	require.Len(t, result.Items, 1)

	expected := models.PolicyResourceDetail{
		Items: []models.ComplianceEntry{
			{
				ExpiresAt:      result.Items[0].ExpiresAt,
				IntegrationID:  integrationID,
				LastUpdated:    result.Items[0].LastUpdated,
				PolicyID:       policyID,
				PolicySeverity: models.SeverityLow,
				ResourceID:     "resource-6",
				ResourceType:   "AWS.S3.Bucket",
				Status:         models.StatusFail,
				Suppressed:     true,
			},
		},
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 3,
		},
		Status: models.StatusError, // overall policy status is ERROR
		Totals: models.ActiveSuppressCount{
			Active: models.StatusCount{
				Error: 3,
				Fail:  3,
				Pass:  3,
			},
			Suppressed: models.StatusCount{
				Error: 3,
				Fail:  3,
				Pass:  3,
			},
		},
	}
	assert.Equal(t, expected, result)

	// Get the next page - the result is almost the same
	input = models.LambdaInput{
		DescribePolicy: &models.DescribePolicyInput{
			PolicyID:   policyID,
			Page:       2,
			PageSize:   1,
			Status:     models.StatusFail,
			Suppressed: aws.Bool(true),
		},
	}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	require.Len(t, result.Items, 1)
	expected.Items[0].ExpiresAt = result.Items[0].ExpiresAt
	expected.Items[0].LastUpdated = result.Items[0].LastUpdated
	expected.Items[0].ResourceID = "resource-8"
	expected.Paging.ThisPage = 2
	assert.Equal(t, expected, result)
}

// A resource which doesn't exist returns empty results.
//
// We don't return 404 because a resource might exist but have no policies applied to it.
func describeResourceEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DescribeResource: &models.DescribeResourceInput{ResourceID: "no-such-resource"},
	}

	var result models.PolicyResourceDetail
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.PolicyResourceDetail{
		Items:  []models.ComplianceEntry{},
		Status: models.StatusPass,
	}
	assert.Equal(t, expected, result)
}

func describeResource(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DescribeResource: &models.DescribeResourceInput{ResourceID: "arn:aws:s3:::my-bucket"},
	}

	var result models.PolicyResourceDetail
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.PolicyResourceDetail{
		Items: []models.ComplianceEntry{
			statuses[3], // sorted by policy ID
			statuses[0],
			statuses[1],
		},
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 1,
		},
		Status: models.StatusError,
		Totals: models.ActiveSuppressCount{
			Active: models.StatusCount{
				Error: 1,
				Pass:  1,
			},
			Suppressed: models.StatusCount{
				Fail: 1,
			},
		},
	}
	assert.Equal(t, expected, result)
}

func getOrgOverviewEmpty(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetOrgOverview: &models.GetOrgOverviewInput{},
	}

	var result models.OrgSummary
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	// empty lists are initialized
	expected := models.OrgSummary{
		AppliedPolicies: models.StatusCountBySeverity{},
		ScannedResources: models.ScannedResources{
			ByType: []models.ResourceOfType{},
		},
		TopFailingPolicies:  []models.PolicySummary{},
		TopFailingResources: []models.ResourceSummary{},
	}
	assert.Equal(t, expected, result)
}

func getOrgOverview(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetOrgOverview: &models.GetOrgOverviewInput{},
	}
	var result models.OrgSummary
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.OrgSummary{
		AppliedPolicies: models.StatusCountBySeverity{
			Critical: models.StatusCount{
				Pass: 2,
			},
			High: models.StatusCount{
				Error: 1,
			},
			Medium: models.StatusCount{
				Fail: 1,
			},
		},
		ScannedResources: models.ScannedResources{
			ByType: []models.ResourceOfType{
				{
					Count: models.StatusCount{
						Pass: 1,
					},
					Type: "AWS.CloudTrail",
				},
				{
					Count: models.StatusCount{
						Error: 1,
						Fail:  1,
					},
					Type: "AWS.S3.Bucket",
				},
			},
		},
		TopFailingPolicies: []models.PolicySummary{
			{
				Count: models.StatusCount{
					Error: 1,
				},
				ID:       "AWS-S3-EncryptionEnabled",
				Severity: models.SeverityHigh,
			},
			{
				Count: models.StatusCount{
					Fail: 1,
				},
				ID:       "AWS-S3-Versioning",
				Severity: models.SeverityMedium,
			},
		},
		TopFailingResources: []models.ResourceSummary{
			{
				Count: models.StatusCountBySeverity{
					Critical: models.StatusCount{
						Pass: 1,
					},
					High: models.StatusCount{
						Error: 1, // 1 HIGH error puts this bucket at top of list
					},
				},
				ID:   "arn:aws:s3:::my-bucket",
				Type: "AWS.S3.Bucket",
			},
			{
				Count: models.StatusCountBySeverity{
					Medium: models.StatusCount{
						Fail: 1,
					},
				},
				ID:   "arn:aws:s3:::my-other-bucket",
				Type: "AWS.S3.Bucket",
			},
		},
	}

	// sort scanned resources by type name
	sort.Slice(result.ScannedResources.ByType, func(i, j int) bool {
		return result.ScannedResources.ByType[i].Type < result.ScannedResources.ByType[j].Type
	})
	assert.Equal(t, expected, result)
}

func getOrgOverviewCustomLimit(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetOrgOverview: &models.GetOrgOverviewInput{LimitTopFailing: 1},
	}
	var result models.OrgSummary
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	policies, resources := result.TopFailingPolicies, result.TopFailingResources
	require.Len(t, policies, 1)
	assert.Equal(t, "AWS-S3-EncryptionEnabled", policies[0].ID)

	require.Len(t, result.TopFailingResources, 1)
	assert.Equal(t, "arn:aws:s3:::my-bucket", resources[0].ID)
}

func update(t *testing.T) {
	input := models.LambdaInput{
		UpdateMetadata: &models.UpdateMetadataInput{
			PolicyID: "AWS-S3-Versioning",
			Severity: "INFO",
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Verify severity and suppressions were overwritten
	input = models.LambdaInput{
		GetStatus: &models.GetStatusInput{
			PolicyID:   statuses[1].PolicyID,
			ResourceID: statuses[1].ResourceID,
		},
	}
	var result models.ComplianceEntry
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	statuses[1].PolicySeverity = "INFO"
	statuses[1].Suppressed = false
	assert.Equal(t, statuses[1], result)

	// Verify severity and suppressions were overwritten
	input = models.LambdaInput{
		GetStatus: &models.GetStatusInput{
			PolicyID:   statuses[2].PolicyID,
			ResourceID: statuses[2].ResourceID,
		},
	}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	statuses[2].PolicySeverity = "INFO"
	assert.Equal(t, statuses[2], result)
}

func deleteBatch(t *testing.T) {
	input := models.LambdaInput{
		DeleteStatus: &models.DeleteStatusInput{
			Entries: []models.DeleteStatusEntry{
				{
					Policy: &models.DeletePolicy{
						ID:            "AWS-S3-Versioning",
						ResourceTypes: []string{"AWS.KMS.Key", "AWS.S3.Bucket"},
					},
				},
				{
					Resource: &models.DeleteResource{ID: "arn:aws:cloudtrail:222222222222::my-trail"},
				},
			},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Trying to get any of the deleted entries now returns a 404
	input = models.LambdaInput{
		GetStatus: &models.GetStatusInput{
			PolicyID:   "AWS-S3-Versioning",
			ResourceID: "arn:aws:s3:::my-bucket",
		},
	}
	statusCode, err = apiClient.Invoke(&input, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)

	input = models.LambdaInput{
		GetStatus: &models.GetStatusInput{
			PolicyID:   "AWS-S3-Versioning",
			ResourceID: "arn:aws:s3:::my-other-bucket",
		},
	}
	statusCode, err = apiClient.Invoke(&input, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)

	input = models.LambdaInput{
		GetStatus: &models.GetStatusInput{
			PolicyID:   "AWS-Cloudtrail-Encryption",
			ResourceID: "arn:aws:cloudtrail:222222222222::my-trail",
		},
	}
	statusCode, err = apiClient.Invoke(&input, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}
