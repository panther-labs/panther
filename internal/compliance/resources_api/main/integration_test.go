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
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/gateway/resources/client"
	"github.com/panther-labs/panther/api/gateway/resources/client/operations"
	"github.com/panther-labs/panther/api/gateway/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

const stackName = "panther-bootstrap-gateway"

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	httpClient      = gatewayapi.GatewayClient(awsSession)
	apiClient       *client.PantherResourcesAPI

	bucket = &models.Resource{
		Attributes:       map[string]interface{}{"Panther": "Labs"},
		ComplianceStatus: models.ComplianceStatusPASS,
		ID:               models.ResourceID("arn:aws:s3:::my-bucket"),
		IntegrationID:    models.IntegrationID("df6652ff-22d7-4c6a-a9ec-3fe50fadbbbf"),
		IntegrationType:  models.IntegrationTypeAws,
		Type:             models.ResourceType("AWS.S3.Bucket"),
	}
	key = &models.Resource{
		Attributes:       map[string]interface{}{"Panther": "Labs"},
		ComplianceStatus: models.ComplianceStatusPASS,
		ID:               models.ResourceID("arn:aws:kms:us-west-2:111111111111:key/09510b31-48bf-464f-8c16-c5669e414c4a"),
		IntegrationID:    models.IntegrationID("df6652ff-22d7-4c6a-a9ec-3fe50fadbbbf"),
		IntegrationType:  models.IntegrationTypeAws,
		Type:             models.ResourceType("AWS.KMS.Key"),
	}
	queue = &models.Resource{
		Attributes:       map[string]interface{}{"Panther": "Labs"},
		ComplianceStatus: models.ComplianceStatusPASS,
		ID:               models.ResourceID("arn:aws:sqs:us-west-2:222222222222:my-queue"),
		IntegrationID:    models.IntegrationID("240fcd50-11c3-496a-ae5a-61ab8e698041"),
		IntegrationType:  models.IntegrationTypeAws,
		Type:             models.ResourceType("AWS.SQS.Queue"),
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
		&cloudformation.DescribeStacksInput{StackName: aws.String(stackName)})
	require.NoError(t, err)
	var endpoint string
	for _, output := range response.Stacks[0].Outputs {
		if aws.StringValue(output.OutputKey) == "ResourcesApiEndpoint" {
			endpoint = *output.OutputValue
			break
		}
	}

	// Reset Dynamo tables and build API client
	require.NoError(t, testutils.ClearDynamoTable(awsSession, "panther-resources"))
	require.NoError(t, testutils.ClearDynamoTable(awsSession, "panther-compliance"))
	require.NotEmpty(t, endpoint)
	apiClient = client.NewHTTPClientWithConfig(nil, client.DefaultTransportConfig().
		WithBasePath("/v1").WithHost(endpoint))

	t.Run("AddResource", func(t *testing.T) {
		t.Run("AddEmpty", addEmpty)
		t.Run("AddInvalid", addInvalid)
		t.Run("AddSuccess", addSuccess)
	})

	t.Run("GetResource", func(t *testing.T) {
		t.Run("GetEmpty", getEmpty)
		t.Run("GetInvalid", getInvalid)
		t.Run("GetNotFound", getNotFound)
		t.Run("GetSuccess", getSuccess)
	})
	if t.Failed() {
		return
	}

	t.Run("OrgOverview", func(t *testing.T) {
		t.Run("OrgOverview", orgOverview)
	})

	t.Run("ListResources", func(t *testing.T) {
		t.Run("ListAll", listAll)
		t.Run("ListPaged", listPaged)
		t.Run("ListFiltered", listFiltered)
	})

	t.Run("DeleteResources", func(t *testing.T) {
		t.Run("DeleteInvalid", deleteInvalid)
		t.Run("DeleteNotFound", deleteNotFound)
		t.Run("DeleteSuccess", deleteSuccess)
	})
}

func addEmpty(t *testing.T) {
	result, err := apiClient.Operations.AddResources(
		&operations.AddResourcesParams{HTTPClient: httpClient})
	assert.Nil(t, result)
	require.Error(t, err)

	require.IsType(t, &operations.AddResourcesBadRequest{}, err)
	badRequest := err.(*operations.AddResourcesBadRequest)
	assert.Equal(t, "Invalid request body", aws.StringValue(badRequest.Payload.Message))
}

func addInvalid(t *testing.T) {
	result, err := apiClient.Operations.AddResources(
		&operations.AddResourcesParams{
			Body: &models.AddResources{
				Resources: []*models.AddResourceEntry{
					{
						Attributes:      map[string]interface{}{}, // missing attributes
						ID:              bucket.ID + "invalid",
						IntegrationID:   bucket.IntegrationID,
						IntegrationType: bucket.IntegrationType,
						Type:            bucket.Type,
					},
				},
			},
			HTTPClient: httpClient,
		})
	assert.Nil(t, result)
	require.Error(t, err)

	require.IsType(t, &operations.AddResourcesBadRequest{}, err)
	badRequest := err.(*operations.AddResourcesBadRequest)
	assert.Equal(t,
		"resources[0].attributes cannot be empty",
		aws.StringValue(badRequest.Payload.Message))
}

func addSuccess(t *testing.T) {
	result, err := apiClient.Operations.AddResources(
		&operations.AddResourcesParams{
			Body: &models.AddResources{
				Resources: []*models.AddResourceEntry{
					// Add several different resources
					{
						Attributes:      bucket.Attributes,
						ID:              bucket.ID,
						IntegrationID:   bucket.IntegrationID,
						IntegrationType: bucket.IntegrationType,
						Type:            bucket.Type,
					},
					{
						Attributes:      key.Attributes,
						ID:              key.ID,
						IntegrationID:   key.IntegrationID,
						IntegrationType: key.IntegrationType,
						Type:            key.Type,
					},
					{
						Attributes:      queue.Attributes,
						ID:              queue.ID,
						IntegrationID:   queue.IntegrationID,
						IntegrationType: queue.IntegrationType,
						Type:            queue.Type,
					},
				},
			},
			HTTPClient: httpClient,
		})
	assert.Equal(t, &operations.AddResourcesCreated{}, result)
	assert.NoError(t, err)
}

func getEmpty(t *testing.T) {
	result, err := apiClient.Operations.GetResource(
		&operations.GetResourceParams{HTTPClient: httpClient})
	assert.Nil(t, result)
	require.Error(t, err)

	require.IsType(t, &operations.GetResourceBadRequest{}, err)
	badRequest := err.(*operations.GetResourceBadRequest)
	assert.Equal(t,
		"Missing required request parameters: [resourceId]",
		aws.StringValue(badRequest.Payload.Message))
}

func getInvalid(t *testing.T) {
	result, err := apiClient.Operations.GetResource(
		&operations.GetResourceParams{
			HTTPClient: httpClient,
		})
	assert.Nil(t, result)
	require.Error(t, err)

	require.IsType(t, &operations.GetResourceBadRequest{}, err)
	badRequest := err.(*operations.GetResourceBadRequest)
	assert.Equal(t,
		"Missing required request parameters: [resourceId]",
		aws.StringValue(badRequest.Payload.Message))
}

func getNotFound(t *testing.T) {
	result, err := apiClient.Operations.GetResource(
		&operations.GetResourceParams{
			ResourceID: "arn:aws:s3:::no-such-bucket",
			HTTPClient: httpClient,
		})
	assert.Nil(t, result)
	require.Error(t, err)
	require.IsType(t, &operations.GetResourceNotFound{}, err)
}

func getSuccess(t *testing.T) {
	result, err := apiClient.Operations.GetResource(
		&operations.GetResourceParams{
			ResourceID: string(bucket.ID),
			HTTPClient: httpClient,
		})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NoError(t, result.Payload.Validate(nil))
	bucket.LastModified = result.Payload.LastModified
	require.Equal(t, bucket, result.Payload)
}

func listAll(t *testing.T) {
	result, err := apiClient.Operations.ListResources(
		&operations.ListResourcesParams{
			HTTPClient: httpClient,
		})
	require.NoError(t, err)
	require.Len(t, result.Payload.Resources, 3)

	expected := &models.ResourceList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(1),
		},
		Resources: []*models.Resource{
			// resources will be in alphabetical order by their ID
			// attributes are not included in the list operation
			{
				ComplianceStatus: models.ComplianceStatusPASS,
				Deleted:          false,
				ID:               key.ID,
				IntegrationID:    key.IntegrationID,
				IntegrationType:  key.IntegrationType,
				LastModified:     result.Payload.Resources[0].LastModified,
				Type:             key.Type,
			},
			{
				ComplianceStatus: models.ComplianceStatusPASS,
				Deleted:          false,
				ID:               bucket.ID,
				IntegrationID:    bucket.IntegrationID,
				IntegrationType:  bucket.IntegrationType,
				LastModified:     result.Payload.Resources[1].LastModified,
				Type:             bucket.Type,
			},
			{
				ComplianceStatus: models.ComplianceStatusPASS,
				Deleted:          false,
				ID:               queue.ID,
				IntegrationID:    queue.IntegrationID,
				IntegrationType:  queue.IntegrationType,
				LastModified:     result.Payload.Resources[2].LastModified,
				Type:             queue.Type,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func listPaged(t *testing.T) {
	result, err := apiClient.Operations.ListResources(
		&operations.ListResourcesParams{
			PageSize:   aws.Int64(1),
			SortDir:    aws.String("descending"), // sort by ID descending
			HTTPClient: httpClient,
		})
	require.NoError(t, err)

	expected := &models.ResourceList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(3),
		},
		Resources: []*models.Resource{
			{
				ComplianceStatus: models.ComplianceStatusPASS,
				Deleted:          false,
				ID:               queue.ID,
				IntegrationID:    queue.IntegrationID,
				IntegrationType:  queue.IntegrationType,
				LastModified:     result.Payload.Resources[0].LastModified,
				Type:             queue.Type,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)

	// Page 2
	result, err = apiClient.Operations.ListResources(
		&operations.ListResourcesParams{
			Page:       aws.Int64(2),
			PageSize:   aws.Int64(1),
			SortDir:    aws.String("descending"),
			HTTPClient: httpClient,
		})
	require.NoError(t, err)

	expected = &models.ResourceList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(2),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(3),
		},
		Resources: []*models.Resource{
			{
				ComplianceStatus: models.ComplianceStatusPASS,
				Deleted:          false,
				ID:               bucket.ID,
				IntegrationID:    bucket.IntegrationID,
				IntegrationType:  bucket.IntegrationType,
				LastModified:     result.Payload.Resources[0].LastModified,
				Type:             bucket.Type,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)

	// Page 3
	result, err = apiClient.Operations.ListResources(
		&operations.ListResourcesParams{
			Page:       aws.Int64(3),
			PageSize:   aws.Int64(1),
			SortDir:    aws.String("descending"),
			HTTPClient: httpClient,
		})
	require.NoError(t, err)

	expected = &models.ResourceList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(3),
			TotalItems: aws.Int64(3),
			TotalPages: aws.Int64(3),
		},
		Resources: []*models.Resource{
			{
				ComplianceStatus: models.ComplianceStatusPASS,
				Deleted:          false,
				ID:               key.ID,
				IntegrationID:    key.IntegrationID,
				IntegrationType:  key.IntegrationType,
				LastModified:     result.Payload.Resources[0].LastModified,
				Type:             key.Type,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func listFiltered(t *testing.T) {
	result, err := apiClient.Operations.ListResources(
		&operations.ListResourcesParams{
			Deleted:         aws.Bool(false),
			Fields:          []string{"attributes,id,type"},
			IDContains:      aws.String("MY"), // queue + bucket
			IntegrationID:   aws.String(string(bucket.IntegrationID)),
			IntegrationType: aws.String(string(bucket.IntegrationType)),
			Types:           []string{"AWS.S3.Bucket"},
			HTTPClient:      httpClient,
		})
	require.NoError(t, err)
	require.Len(t, result.Payload.Resources, 1)

	expected := &models.ResourceList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(1),
			TotalItems: aws.Int64(1),
			TotalPages: aws.Int64(1),
		},
		Resources: []*models.Resource{
			{
				Attributes: bucket.Attributes,
				ID:         bucket.ID,
				Type:       bucket.Type,
			},
		},
	}
	assert.Equal(t, expected, result.Payload)
}

func orgOverview(t *testing.T) {
	params := &operations.GetOrgOverviewParams{
		HTTPClient: httpClient,
	}
	result, err := apiClient.Operations.GetOrgOverview(params)
	require.NoError(t, err)

	expected := &models.OrgOverview{
		Resources: []*models.ResourceTypeSummary{
			{
				Count: aws.Int64(1),
				Type:  models.ResourceType("AWS.KMS.Key"),
			},
			{
				Count: aws.Int64(1),
				Type:  models.ResourceType("AWS.S3.Bucket"),
			},
			{
				Count: aws.Int64(1),
				Type:  models.ResourceType("AWS.SQS.Queue"),
			},
		},
	}

	// Sort results by Type
	sort.Slice(result.Payload.Resources, func(i, j int) bool {
		return result.Payload.Resources[i].Type < result.Payload.Resources[j].Type
	})
	assert.Equal(t, expected, result.Payload)
}

func deleteInvalid(t *testing.T) {
	result, err := apiClient.Operations.DeleteResources(&operations.DeleteResourcesParams{
		Body: &models.DeleteResources{
			Resources: []*models.DeleteEntry{},
		},
		HTTPClient: httpClient,
	})
	assert.Nil(t, result)
	require.Error(t, err)

	require.IsType(t, &operations.DeleteResourcesBadRequest{}, err)
	badRequest := err.(*operations.DeleteResourcesBadRequest)
	assert.Equal(t,
		"validation failure list:\nresources in body should have at least 1 items",
		aws.StringValue(badRequest.Payload.Message))
}

// No error is returned if deletes are requested for resources that don't exist
func deleteNotFound(t *testing.T) {
	result, err := apiClient.Operations.DeleteResources(&operations.DeleteResourcesParams{
		Body: &models.DeleteResources{
			Resources: []*models.DeleteEntry{
				{ID: "no-such-resource"},
			},
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.DeleteResourcesOK{}, result)
}

func deleteSuccess(t *testing.T) {
	result, err := apiClient.Operations.DeleteResources(&operations.DeleteResourcesParams{
		Body: &models.DeleteResources{
			Resources: []*models.DeleteEntry{
				{ID: bucket.ID},
				{ID: key.ID},
				{ID: queue.ID},
			},
		},
		HTTPClient: httpClient,
	})
	require.NoError(t, err)
	assert.Equal(t, &operations.DeleteResourcesOK{}, result)

	// Deleted resources should not show up when filtered out
	list, err := apiClient.Operations.ListResources(
		&operations.ListResourcesParams{
			Deleted:    aws.Bool(false),
			HTTPClient: httpClient,
		})
	require.NoError(t, err)
	expected := &models.ResourceList{
		Paging: &models.Paging{
			ThisPage:   aws.Int64(0),
			TotalItems: aws.Int64(0),
			TotalPages: aws.Int64(0),
		},
		Resources: []*models.Resource{},
	}

	assert.Equal(t, expected, list.Payload)

	// Unless you specifically ask for them
	list, err = apiClient.Operations.ListResources(
		&operations.ListResourcesParams{
			Deleted:    aws.Bool(true),
			HTTPClient: httpClient,
		})
	require.NoError(t, err)
	assert.Len(t, list.Payload.Resources, 3)
}
