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
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/gateway/compliance/client"
	"github.com/panther-labs/panther/api/gateway/compliance/client/operations"
	"github.com/panther-labs/panther/api/gateway/compliance/models"
	"github.com/panther-labs/panther/internal/compliance/compliance_api/handlers"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	httpClient      = gatewayapi.GatewayClient(awsSession)
	apiClient       *client.PantherComplianceAPI

	integrationID = models.IntegrationID("f0e95b8b-6d93-4de5-a963-a2974fd2ba72")

	// 5 policies: 1 error, 2 fail (1 suppressed), 2 pass across 3 resources and 4 policies
	statuses = []*models.ComplianceStatus{
		{
			ErrorMessage:   models.ErrorMessage("ZeroDivisionError"),
			PolicyID:       models.PolicyID("AWS-S3-EncryptionEnabled"),
			PolicySeverity: models.PolicySeverityHIGH,
			ResourceID:     models.ResourceID("arn:aws:s3:::my-bucket"),
			ResourceType:   models.ResourceType("AWS.S3.Bucket"),
			Status:         models.StatusERROR,
			Suppressed:     models.Suppressed(false),
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       models.PolicyID("AWS-S3-Versioning"),
			PolicySeverity: models.PolicySeverityMEDIUM,
			ResourceID:     models.ResourceID("arn:aws:s3:::my-bucket"),
			ResourceType:   models.ResourceType("AWS.S3.Bucket"),
			Status:         models.StatusFAIL,
			Suppressed:     models.Suppressed(true),
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       models.PolicyID("AWS-S3-Versioning"),
			PolicySeverity: models.PolicySeverityMEDIUM,
			ResourceID:     models.ResourceID("arn:aws:s3:::my-other-bucket"),
			ResourceType:   models.ResourceType("AWS.S3.Bucket"),
			Status:         models.StatusFAIL,
			Suppressed:     models.Suppressed(false),
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       models.PolicyID("AWS-S3-BlockPublicAccess"),
			PolicySeverity: models.PolicySeverityCRITICAL,
			ResourceID:     models.ResourceID("arn:aws:s3:::my-bucket"),
			ResourceType:   models.ResourceType("AWS.S3.Bucket"),
			Status:         models.StatusPASS,
			Suppressed:     models.Suppressed(false),
			IntegrationID:  integrationID,
		},
		{
			PolicyID:       models.PolicyID("AWS-Cloudtrail-Encryption"),
			PolicySeverity: models.PolicySeverityCRITICAL,
			ResourceID:     models.ResourceID("arn:aws:cloudtrail:123412341234::my-trail"),
			ResourceType:   models.ResourceType("AWS.CloudTrail"),
			Status:         models.StatusPASS,
			Suppressed:     models.Suppressed(false),
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

	// Lookup CloudFormation outputs
	cfnClient := cloudformation.New(awsSession)
	response, err := cfnClient.DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String("panther-bootstrap-gateway")})
	require.NoError(t, err)
	var endpoint string
	for _, output := range response.Stacks[0].Outputs {
		if aws.StringValue(output.OutputKey) == "ComplianceApiEndpoint" {
			endpoint = *output.OutputValue
			break
		}
	}

	// Reset Dynamo table and build API client
	require.NoError(t, testutils.ClearDynamoTable(awsSession, "panther-compliance"))
	require.NotEmpty(t, endpoint)
	apiClient = client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(endpoint))

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
	result, err := apiClient.Operations.SetStatus(&operations.SetStatusParams{
		Body:       &models.SetStatusBatch{Entries: []*models.SetStatus{}},
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)

	require.IsType(t, &operations.SetStatusBadRequest{}, err)
	errorMessage := aws.StringValue(err.(*operations.SetStatusBadRequest).Payload.Message)
	assert.Equal(t, "validation failure list:\nentries in body should have at least 1 items", errorMessage)
}

func setSuccess(t *testing.T) {
	t.Parallel()
	entries := make([]*models.SetStatus, len(statuses))
	for i, status := range statuses {
		entries[i] = &models.SetStatus{
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

	result, err := apiClient.Operations.SetStatus(&operations.SetStatusParams{
		Body:       &models.SetStatusBatch{Entries: entries},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.SetStatusCreated{}, result)
}

func getNotFound(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.GetStatus(&operations.GetStatusParams{
		PolicyID:   "no-such-policy",
		ResourceID: string(statuses[0].ResourceID),
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.GetStatusNotFound{}, err)
}

func getSuccess(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.GetStatus(&operations.GetStatusParams{
		PolicyID:   string(statuses[0].PolicyID),
		ResourceID: string(statuses[0].ResourceID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	for i := 0; i < len(statuses); i++ {
		assert.NotEmpty(t, result.Payload.ExpiresAt)
		statuses[i].ExpiresAt = result.Payload.ExpiresAt
		assert.NotEmpty(t, result.Payload.LastUpdated)
		statuses[i].LastUpdated = result.Payload.LastUpdated
	}
	assert.Equal(t, statuses[0], result.Payload)
}

func describeOrgEmpty(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.DescribeOrg(&operations.DescribeOrgParams{
		Type:       "policy",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.EntireOrg{Policies: []*models.ItemSummary{}, Resources: []*models.ItemSummary{}}
	assert.Equal(t, expected, result.Payload)
}

func describeOrgPolicy(t *testing.T) {
	t.Parallel()

	// org1
	result, err := apiClient.Operations.DescribeOrg(&operations.DescribeOrgParams{
		Type:       "policy",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.EntireOrg{
		Policies: []*models.ItemSummary{
			{
				ID:     aws.String("AWS-S3-EncryptionEnabled"), // 1 HIGH error
				Status: models.StatusERROR,
			},
			{
				ID:     aws.String("AWS-S3-Versioning"), // 1 MEDIUM failure
				Status: models.StatusFAIL,
			},
			// passing policies are sorted by ID
			{
				ID:     aws.String("AWS-Cloudtrail-Encryption"),
				Status: models.StatusPASS,
			},
			{
				ID:     aws.String("AWS-S3-BlockPublicAccess"),
				Status: models.StatusPASS,
			},
		},
		Resources: []*models.ItemSummary{},
	}
	assert.Equal(t, expected, result.Payload)
}

func describeOrgResource(t *testing.T) {
	t.Parallel()

	// org1
	result, err := apiClient.Operations.DescribeOrg(&operations.DescribeOrgParams{
		Type:       "resource",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.EntireOrg{
		Policies: []*models.ItemSummary{},
		Resources: []*models.ItemSummary{
			{
				ID:     aws.String("arn:aws:s3:::my-bucket"), // 1 HIGH error
				Status: models.StatusERROR,
			},
			{
				ID:     aws.String("arn:aws:s3:::my-other-bucket"), // 1 MEDIUM failure
				Status: models.StatusFAIL,
			},
			{
				ID:     aws.String("arn:aws:cloudtrail:123412341234::my-trail"),
				Status: models.StatusPASS,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

// A policy which doesn't exist returns empty results.
//
// We don't return 404 because a disabled policy will not exist in the compliance-api but would
// in the analysis-api
func describePolicyEmpty(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.DescribePolicy(&operations.DescribePolicyParams{
		PolicyID:   "no-such-policy",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.PolicyResourceDetail{
		Items: []*models.ComplianceStatus{},
		Paging: &models.Paging{
			ThisPage:   aws.Int64(0),
			TotalItems: aws.Int64(0),
			TotalPages: aws.Int64(0),
		},
		Status: models.StatusPASS,
		Totals: &models.ActiveSuppressCount{
			Active: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(0),
			},
			Suppressed: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(0),
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func describePolicy(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.DescribePolicy(&operations.DescribePolicyParams{
		PolicyID:   "AWS-Cloudtrail-Encryption",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.PolicyResourceDetail{
		Items: []*models.ComplianceStatus{
			statuses[4],
		},
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(1),
			TotalPages: aws.Int64(1),
		},
		Status: models.StatusPASS,
		Totals: &models.ActiveSuppressCount{
			Active: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(1),
			},
			Suppressed: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(0),
			},
		},
	}
	assert.Equal(t, expected, result.Payload)

	// Query a policy with 2 entries, one of which is suppressed
	result, err = apiClient.Operations.DescribePolicy(&operations.DescribePolicyParams{
		PolicyID:   "AWS-S3-Versioning",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected = &models.PolicyResourceDetail{
		Items: []*models.ComplianceStatus{
			statuses[2],
			statuses[1],
		},
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(2),
			TotalPages: aws.Int64(1),
		},
		Status: models.StatusFAIL,
		Totals: &models.ActiveSuppressCount{
			Active: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(1),
				Pass:  aws.Int64(0),
			},
			Suppressed: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(1),
				Pass:  aws.Int64(0),
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

// Test paging + filtering with more items
func describePolicyPageAndFilter(t *testing.T) {
	t.Parallel()

	// Add 18 entries with 3 copies of each (status, suppressed) combination
	entries := make([]*models.SetStatus, 18)
	integrationID := "52346bf0-e490-480b-a4b5-35fe83c98c17"

	policyID := "copy-policy"

	for i := 0; i < len(entries); i++ {
		var status models.Status
		switch {
		case i < 6:
			status = models.StatusERROR
		case i < 12:
			status = models.StatusFAIL
		default:
			status = models.StatusPASS
		}

		suppressed := false
		if i%2 == 0 {
			suppressed = true
		}

		entries[i] = &models.SetStatus{
			PolicyID:       models.PolicyID(policyID),
			PolicySeverity: models.PolicySeverityLOW,
			ResourceID:     models.ResourceID(fmt.Sprintf("resource-%d", i)),
			ResourceType:   "AWS.S3.Bucket",
			Status:         status,
			Suppressed:     models.Suppressed(suppressed),
			IntegrationID:  models.IntegrationID(integrationID),
		}
	}

	_, err := apiClient.Operations.SetStatus(&operations.SetStatusParams{
		Body:       &models.SetStatusBatch{Entries: entries},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	// Fetch suppressed FAIL entries with pageSize=1
	result, err := apiClient.Operations.DescribePolicy(&operations.DescribePolicyParams{
		PageSize:   aws.Int64(1),
		PolicyID:   policyID,
		Status:     aws.String(string(models.StatusFAIL)),
		Suppressed: aws.Bool(true),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	require.Len(t, result.Payload.Items, 1)

	expected := &models.PolicyResourceDetail{
		Items: []*models.ComplianceStatus{
			{
				ExpiresAt:      result.Payload.Items[0].ExpiresAt,
				IntegrationID:  models.IntegrationID(integrationID),
				LastUpdated:    result.Payload.Items[0].LastUpdated,
				PolicyID:       models.PolicyID(policyID),
				PolicySeverity: models.PolicySeverityLOW,
				ResourceID:     "resource-6",
				ResourceType:   "AWS.S3.Bucket",
				Status:         models.StatusFAIL,
				Suppressed:     models.Suppressed(true),
			},
		},
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(3),
		},
		Status: models.StatusERROR, // overall policy status is ERROR
		Totals: &models.ActiveSuppressCount{
			Active: &models.StatusCount{
				Error: aws.Int64(3),
				Fail:  aws.Int64(3),
				Pass:  aws.Int64(3),
			},
			Suppressed: &models.StatusCount{
				Error: aws.Int64(3),
				Fail:  aws.Int64(3),
				Pass:  aws.Int64(3),
			},
		},
	}
	assert.Equal(t, expected, result.Payload)

	// Get the next page - the result is almost the same
	result, err = apiClient.Operations.DescribePolicy(&operations.DescribePolicyParams{
		Page:       aws.Int64(2),
		PageSize:   aws.Int64(1),
		PolicyID:   policyID,
		Status:     aws.String(string(models.StatusFAIL)),
		Suppressed: aws.Bool(true),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	require.Len(t, result.Payload.Items, 1)
	expected.Items[0].ExpiresAt = result.Payload.Items[0].ExpiresAt
	expected.Items[0].LastUpdated = result.Payload.Items[0].LastUpdated
	expected.Items[0].ResourceID = "resource-8"
	expected.Paging.ThisPage = aws.Int64(2)
	assert.Equal(t, expected, result.Payload)
}

// A resource which doesn't exist returns empty results.
//
// We don't return 404 because a resource might exist but have no policies applied to it.
func describeResourceEmpty(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.DescribeResource(&operations.DescribeResourceParams{
		ResourceID: "no-such-resource",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.PolicyResourceDetail{
		Items: []*models.ComplianceStatus{},
		Paging: &models.Paging{
			ThisPage:   aws.Int64(0),
			TotalItems: aws.Int64(0),
			TotalPages: aws.Int64(0),
		},
		Status: models.StatusPASS,
		Totals: &models.ActiveSuppressCount{
			Active: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(0),
			},
			Suppressed: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(0),
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func describeResource(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.DescribeResource(&operations.DescribeResourceParams{
		ResourceID: "arn:aws:s3:::my-bucket",
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.PolicyResourceDetail{
		Items: []*models.ComplianceStatus{
			statuses[3], // sorted by policy ID
			statuses[0],
			statuses[1],
		},
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(1),
		},
		Status: models.StatusERROR,
		Totals: &models.ActiveSuppressCount{
			Active: &models.StatusCount{
				Error: aws.Int64(1),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(1),
			},
			Suppressed: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(1),
				Pass:  aws.Int64(0),
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func getOrgOverviewEmpty(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.GetOrgOverview(&operations.GetOrgOverviewParams{
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.OrgSummary{
		AppliedPolicies:     handlers.NewStatusCountBySeverity(),
		ScannedResources:    &models.ScannedResources{ByType: []*models.ResourceOfType{}},
		TopFailingPolicies:  []*models.PolicySummary{},
		TopFailingResources: []*models.ResourceSummary{},
	}
	assert.Equal(t, expected, result.Payload)
}

func getOrgOverview(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.GetOrgOverview(&operations.GetOrgOverviewParams{
		HTTPClient: httpClient,
	})
	require.NoError(t, err)

	expected := &models.OrgSummary{
		AppliedPolicies: &models.StatusCountBySeverity{
			Critical: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(2),
			},
			High: &models.StatusCount{
				Error: aws.Int64(1),
				Fail:  aws.Int64(0),
				Pass:  aws.Int64(0),
			},
			Medium: &models.StatusCount{
				Error: aws.Int64(0),
				Fail:  aws.Int64(1),
				Pass:  aws.Int64(0),
			},
			Low:  handlers.NewStatusCount(),
			Info: handlers.NewStatusCount(),
		},
		ScannedResources: &models.ScannedResources{
			ByType: []*models.ResourceOfType{
				{
					Count: &models.StatusCount{
						Error: aws.Int64(0),
						Fail:  aws.Int64(0),
						Pass:  aws.Int64(1),
					},
					Type: "AWS.CloudTrail",
				},
				{
					Count: &models.StatusCount{
						Error: aws.Int64(1),
						Fail:  aws.Int64(1),
						Pass:  aws.Int64(0),
					},
					Type: "AWS.S3.Bucket",
				},
			},
		},
		TopFailingPolicies: []*models.PolicySummary{
			{
				Count: &models.StatusCount{
					Error: aws.Int64(1),
					Fail:  aws.Int64(0),
					Pass:  aws.Int64(0),
				},
				ID:       "AWS-S3-EncryptionEnabled",
				Severity: models.PolicySeverityHIGH,
			},
			{
				Count: &models.StatusCount{
					Error: aws.Int64(0),
					Fail:  aws.Int64(1),
					Pass:  aws.Int64(0),
				},
				ID:       "AWS-S3-Versioning",
				Severity: models.PolicySeverityMEDIUM,
			},
		},
		TopFailingResources: []*models.ResourceSummary{
			{
				Count: &models.StatusCountBySeverity{
					Critical: &models.StatusCount{
						Error: aws.Int64(0),
						Fail:  aws.Int64(0),
						Pass:  aws.Int64(1),
					},
					High: &models.StatusCount{
						Error: aws.Int64(1), // 1 HIGH error puts this bucket at top of list
						Fail:  aws.Int64(0),
						Pass:  aws.Int64(0),
					},
					Medium: handlers.NewStatusCount(),
					Low:    handlers.NewStatusCount(),
					Info:   handlers.NewStatusCount(),
				},
				ID:   "arn:aws:s3:::my-bucket",
				Type: "AWS.S3.Bucket",
			},
			{
				Count: &models.StatusCountBySeverity{
					Critical: handlers.NewStatusCount(),
					High:     handlers.NewStatusCount(),
					Medium: &models.StatusCount{
						Error: aws.Int64(0),
						Fail:  aws.Int64(1),
						Pass:  aws.Int64(0),
					},
					Low:  handlers.NewStatusCount(),
					Info: handlers.NewStatusCount(),
				},
				ID:   "arn:aws:s3:::my-other-bucket",
				Type: "AWS.S3.Bucket",
			},
		},
	}

	// sort scanned resources by type name
	sort.Slice(result.Payload.ScannedResources.ByType, func(i, j int) bool {
		return result.Payload.ScannedResources.ByType[i].Type < result.Payload.ScannedResources.ByType[j].Type
	})
	assert.Equal(t, expected, result.Payload)
}

func getOrgOverviewCustomLimit(t *testing.T) {
	t.Parallel()
	result, err := apiClient.Operations.GetOrgOverview(&operations.GetOrgOverviewParams{
		LimitTopFailing: aws.Int64(1),
		HTTPClient:      httpClient,
	})
	require.NoError(t, err)

	policies, resources := result.Payload.TopFailingPolicies, result.Payload.TopFailingResources
	require.Len(t, policies, 1)
	assert.Equal(t, models.PolicyID("AWS-S3-EncryptionEnabled"), policies[0].ID)

	require.Len(t, result.Payload.TopFailingResources, 1)
	assert.Equal(t, models.ResourceID("arn:aws:s3:::my-bucket"), resources[0].ID)
}

func update(t *testing.T) {
	result, err := apiClient.Operations.UpdateMetadata(&operations.UpdateMetadataParams{
		Body: &models.UpdateMetadata{
			PolicyID:     "AWS-S3-Versioning",
			Severity:     "INFO",
			Suppressions: nil,
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.UpdateMetadataOK{}, result)

	// Verify severity and suppressions were overwritten
	entry, err := apiClient.Operations.GetStatus(&operations.GetStatusParams{
		PolicyID:   string(statuses[1].PolicyID),
		ResourceID: string(statuses[1].ResourceID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	statuses[1].PolicySeverity = "INFO"
	statuses[1].Suppressed = false
	assert.Equal(t, statuses[1], entry.Payload)

	// Verify severity and suppressions were overwritten
	entry, err = apiClient.Operations.GetStatus(&operations.GetStatusParams{
		PolicyID:   string(statuses[2].PolicyID),
		ResourceID: string(statuses[2].ResourceID),
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	statuses[2].PolicySeverity = "INFO" // still suppressed = false
	assert.Equal(t, statuses[2], entry.Payload)
}

func deleteBatch(t *testing.T) {
	result, err := apiClient.Operations.DeleteStatus(&operations.DeleteStatusParams{
		Body: &models.DeleteStatusBatch{
			Entries: []*models.DeleteStatus{
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
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.DeleteStatusOK{}, result)

	// Trying to get any of the deleted entries now returns a 404
	getResult, err := apiClient.Operations.GetStatus(&operations.GetStatusParams{
		PolicyID:   "AWS-S3-Versioning",
		ResourceID: "arn:aws:s3:::my-bucket",
		HTTPClient: httpClient,
	})
	require.Error(t, err)
	assert.IsType(t, &operations.GetStatusNotFound{}, err)
	assert.Nil(t, getResult)

	getResult, err = apiClient.Operations.GetStatus(&operations.GetStatusParams{
		PolicyID:   "AWS-S3-Versioning",
		ResourceID: "arn:aws:s3:::my-other-bucket",
		HTTPClient: httpClient,
	})
	require.Error(t, err)
	assert.IsType(t, &operations.GetStatusNotFound{}, err)
	assert.Nil(t, getResult)

	getResult, err = apiClient.Operations.GetStatus(&operations.GetStatusParams{
		PolicyID:   "AWS-Cloudtrail-Encryption",
		ResourceID: "arn:aws:cloudtrail:222222222222::my-trail",
		HTTPClient: httpClient,
	})
	require.Error(t, err)
	assert.IsType(t, &operations.GetStatusNotFound{}, err)
	assert.Nil(t, getResult)
}
