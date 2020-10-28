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
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	apiClient       = gatewayapi.NewClient(lambda.New(awsSession), "panther-resources-api")

	bucket = &models.Resource{
		Attributes:      map[string]interface{}{"Panther": "Labs"},
		ID:              "arn:aws:s3:::my-bucket",
		IntegrationID:   "df6652ff-22d7-4c6a-a9ec-3fe50fadbbbf",
		IntegrationType: "aws",
		Type:            "AWS.S3.Bucket",
	}
	key = &models.Resource{
		Attributes:      map[string]interface{}{"Panther": "Labs"},
		ID:              "arn:aws:kms:us-west-2:111111111111:key/09510b31-48bf-464f-8c16-c5669e414c4a",
		IntegrationID:   "df6652ff-22d7-4c6a-a9ec-3fe50fadbbbf",
		IntegrationType: "aws",
		Type:            "AWS.KMS.Key",
	}
	queue = &models.Resource{
		Attributes:      map[string]interface{}{"Panther": "Labs"},
		ID:              "arn:aws:sqs:us-west-2:222222222222:my-queue",
		IntegrationID:   "240fcd50-11c3-496a-ae5a-61ab8e698041",
		IntegrationType: "aws",
		Type:            "AWS.SQS.Queue",
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

	// Reset Dynamo tables
	require.NoError(t, testutils.ClearDynamoTable(awsSession, "panther-resources"))
	require.NoError(t, testutils.ClearDynamoTable(awsSession, "panther-compliance"))

	t.Run("AddResource", func(t *testing.T) {
		t.Run("AddInvalid", addInvalid)
		t.Run("AddSuccess", addSuccess)
	})

	// TODO - flaky integration test (don't worry about compliance status)
	t.Run("GetResource", func(t *testing.T) {
		t.Run("GetInvalid", getInvalid)
		t.Run("GetNotFound", getNotFound)
		t.Run("GetSuccess", getSuccess)
	})
	if t.Failed() {
		return
	}
	//
	//t.Run("OrgOverview", func(t *testing.T) {
	//	t.Run("OrgOverview", orgOverview)
	//})
	//
	//t.Run("ListResources", func(t *testing.T) {
	//	t.Run("ListAll", listAll)
	//	t.Run("ListPaged", listPaged)
	//	t.Run("ListFiltered", listFiltered)
	//})
	//
	//t.Run("DeleteResources", func(t *testing.T) {
	//	t.Run("DeleteInvalid", deleteInvalid)
	//	t.Run("DeleteNotFound", deleteNotFound)
	//	t.Run("DeleteSuccess", deleteSuccess)
	//})
}

func addInvalid(t *testing.T) {
	input := models.LambdaInput{
		AddResources: &models.AddResourcesInput{
			Resources: []models.AddResourceEntry{
				{
					Attributes:      map[string]interface{}{}, // missing attributes
					ID:              bucket.ID + "invalid",
					IntegrationID:   bucket.IntegrationID,
					IntegrationType: bucket.IntegrationType,
					Type:            bucket.Type,
				},
			},
		},
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)
	assert.Equal(t,
		"resources[0].attributes cannot be empty",
		err.Error())
}

func addSuccess(t *testing.T) {
	input := models.LambdaInput{
		AddResources: &models.AddResourcesInput{
			Resources: []models.AddResourceEntry{
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
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, statusCode)
}

func getInvalid(t *testing.T) {
	input := models.LambdaInput{
		GetResource: &models.GetResourceInput{},
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)
	assert.Equal(t,
		"resources[0].attributes cannot be empty",
		err.Error())
}

func getNotFound(t *testing.T) {
	input := models.LambdaInput{
		GetResource: &models.GetResourceInput{ID: "arn:aws:s3:::no-such-bucket"},
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

func getSuccess(t *testing.T) {
	input := models.LambdaInput{
		GetResource: &models.GetResourceInput{ID: bucket.ID},
	}
	var result models.Resource
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	bucket.LastModified = result.LastModified
	assert.NotEmpty(t, result.ComplianceStatus) // doesn't matter what the status actually is
	result.ComplianceStatus = ""
	require.Equal(t, bucket, result)
}

//
//func listAll(t *testing.T) {
//	result, err := apiClient.Operations.ListResources(
//		&operations.ListResourcesParams{
//			HTTPClient: httpClient,
//		})
//	require.NoError(t, err)
//	require.Len(t, result.Payload.Resources, 3)
//
//	expected := &models.ResourceList{
//		Paging: &models.Paging{
//			ThisPage:   aws.Int64(1),
//			TotalItems: aws.Int64(3),
//			TotalPages: aws.Int64(1),
//		},
//		Resources: []*models.Resource{
//			// resources will be in alphabetical order by their ID
//			// attributes are not included in the list operation
//			{
//				ComplianceStatus: models.ComplianceStatusPASS,
//				Deleted:          false,
//				ID:               key.ID,
//				IntegrationID:    key.IntegrationID,
//				IntegrationType:  key.IntegrationType,
//				LastModified:     result.Payload.Resources[0].LastModified,
//				Type:             key.Type,
//			},
//			{
//				ComplianceStatus: models.ComplianceStatusPASS,
//				Deleted:          false,
//				ID:               bucket.ID,
//				IntegrationID:    bucket.IntegrationID,
//				IntegrationType:  bucket.IntegrationType,
//				LastModified:     result.Payload.Resources[1].LastModified,
//				Type:             bucket.Type,
//			},
//			{
//				ComplianceStatus: models.ComplianceStatusPASS,
//				Deleted:          false,
//				ID:               queue.ID,
//				IntegrationID:    queue.IntegrationID,
//				IntegrationType:  queue.IntegrationType,
//				LastModified:     result.Payload.Resources[2].LastModified,
//				Type:             queue.Type,
//			},
//		},
//	}
//	assert.Equal(t, expected, result.Payload)
//}
//
//func listPaged(t *testing.T) {
//	result, err := apiClient.Operations.ListResources(
//		&operations.ListResourcesParams{
//			PageSize:   aws.Int64(1),
//			SortDir:    aws.String("descending"), // sort by ID descending
//			HTTPClient: httpClient,
//		})
//	require.NoError(t, err)
//
//	expected := &models.ResourceList{
//		Paging: &models.Paging{
//			ThisPage:   aws.Int64(1),
//			TotalItems: aws.Int64(3),
//			TotalPages: aws.Int64(3),
//		},
//		Resources: []*models.Resource{
//			{
//				ComplianceStatus: models.ComplianceStatusPASS,
//				Deleted:          false,
//				ID:               queue.ID,
//				IntegrationID:    queue.IntegrationID,
//				IntegrationType:  queue.IntegrationType,
//				LastModified:     result.Payload.Resources[0].LastModified,
//				Type:             queue.Type,
//			},
//		},
//	}
//	assert.Equal(t, expected, result.Payload)
//
//	// Page 2
//	result, err = apiClient.Operations.ListResources(
//		&operations.ListResourcesParams{
//			Page:       aws.Int64(2),
//			PageSize:   aws.Int64(1),
//			SortDir:    aws.String("descending"),
//			HTTPClient: httpClient,
//		})
//	require.NoError(t, err)
//
//	expected = &models.ResourceList{
//		Paging: &models.Paging{
//			ThisPage:   aws.Int64(2),
//			TotalItems: aws.Int64(3),
//			TotalPages: aws.Int64(3),
//		},
//		Resources: []*models.Resource{
//			{
//				ComplianceStatus: models.ComplianceStatusPASS,
//				Deleted:          false,
//				ID:               bucket.ID,
//				IntegrationID:    bucket.IntegrationID,
//				IntegrationType:  bucket.IntegrationType,
//				LastModified:     result.Payload.Resources[0].LastModified,
//				Type:             bucket.Type,
//			},
//		},
//	}
//	assert.Equal(t, expected, result.Payload)
//
//	// Page 3
//	result, err = apiClient.Operations.ListResources(
//		&operations.ListResourcesParams{
//			Page:       aws.Int64(3),
//			PageSize:   aws.Int64(1),
//			SortDir:    aws.String("descending"),
//			HTTPClient: httpClient,
//		})
//	require.NoError(t, err)
//
//	expected = &models.ResourceList{
//		Paging: &models.Paging{
//			ThisPage:   aws.Int64(3),
//			TotalItems: aws.Int64(3),
//			TotalPages: aws.Int64(3),
//		},
//		Resources: []*models.Resource{
//			{
//				ComplianceStatus: models.ComplianceStatusPASS,
//				Deleted:          false,
//				ID:               key.ID,
//				IntegrationID:    key.IntegrationID,
//				IntegrationType:  key.IntegrationType,
//				LastModified:     result.Payload.Resources[0].LastModified,
//				Type:             key.Type,
//			},
//		},
//	}
//	assert.Equal(t, expected, result.Payload)
//}
//
//func listFiltered(t *testing.T) {
//	result, err := apiClient.Operations.ListResources(
//		&operations.ListResourcesParams{
//			Deleted:         aws.Bool(false),
//			Fields:          []string{"attributes,id,type"},
//			IDContains:      aws.String("MY"), // queue + bucket
//			IntegrationID:   aws.String(string(bucket.IntegrationID)),
//			IntegrationType: aws.String(string(bucket.IntegrationType)),
//			Types:           []string{"AWS.S3.Bucket"},
//			HTTPClient:      httpClient,
//		})
//	require.NoError(t, err)
//	require.Len(t, result.Payload.Resources, 1)
//
//	expected := &models.ResourceList{
//		Paging: &models.Paging{
//			ThisPage:   aws.Int64(1),
//			TotalItems: aws.Int64(1),
//			TotalPages: aws.Int64(1),
//		},
//		Resources: []*models.Resource{
//			{
//				Attributes: bucket.Attributes,
//				ID:         bucket.ID,
//				Type:       bucket.Type,
//			},
//		},
//	}
//	assert.Equal(t, expected, result.Payload)
//}
//
//func orgOverview(t *testing.T) {
//	params := &operations.GetOrgOverviewParams{
//		HTTPClient: httpClient,
//	}
//	result, err := apiClient.Operations.GetOrgOverview(params)
//	require.NoError(t, err)
//
//	expected := &models.OrgOverview{
//		Resources: []*models.ResourceTypeSummary{
//			{
//				Count: aws.Int64(1),
//				Type:  models.ResourceType("AWS.KMS.Key"),
//			},
//			{
//				Count: aws.Int64(1),
//				Type:  models.ResourceType("AWS.S3.Bucket"),
//			},
//			{
//				Count: aws.Int64(1),
//				Type:  models.ResourceType("AWS.SQS.Queue"),
//			},
//		},
//	}
//
//	// Sort results by Type
//	sort.Slice(result.Payload.Resources, func(i, j int) bool {
//		return result.Payload.Resources[i].Type < result.Payload.Resources[j].Type
//	})
//	assert.Equal(t, expected, result.Payload)
//}
//
//func deleteInvalid(t *testing.T) {
//	result, err := apiClient.Operations.DeleteResources(&operations.DeleteResourcesParams{
//		Body: &models.DeleteResources{
//			Resources: []*models.DeleteEntry{},
//		},
//		HTTPClient: httpClient,
//	})
//	assert.Nil(t, result)
//	require.Error(t, err)
//
//	require.IsType(t, &operations.DeleteResourcesBadRequest{}, err)
//	badRequest := err.(*operations.DeleteResourcesBadRequest)
//	assert.Equal(t,
//		"validation failure list:\nresources in body should have at least 1 items",
//		aws.StringValue(badRequest.Payload.Message))
//}
//
//// No error is returned if deletes are requested for resources that don't exist
//func deleteNotFound(t *testing.T) {
//	result, err := apiClient.Operations.DeleteResources(&operations.DeleteResourcesParams{
//		Body: &models.DeleteResources{
//			Resources: []*models.DeleteEntry{
//				{ID: "no-such-resource"},
//			},
//		},
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	assert.Equal(t, &operations.DeleteResourcesOK{}, result)
//}
//
//func deleteSuccess(t *testing.T) {
//	result, err := apiClient.Operations.DeleteResources(&operations.DeleteResourcesParams{
//		Body: &models.DeleteResources{
//			Resources: []*models.DeleteEntry{
//				{ID: bucket.ID},
//				{ID: key.ID},
//				{ID: queue.ID},
//			},
//		},
//		HTTPClient: httpClient,
//	})
//	require.NoError(t, err)
//	assert.Equal(t, &operations.DeleteResourcesOK{}, result)
//
//	// Deleted resources should not show up when filtered out
//	list, err := apiClient.Operations.ListResources(
//		&operations.ListResourcesParams{
//			Deleted:    aws.Bool(false),
//			HTTPClient: httpClient,
//		})
//	require.NoError(t, err)
//	expected := &models.ResourceList{
//		Paging: &models.Paging{
//			ThisPage:   aws.Int64(0),
//			TotalItems: aws.Int64(0),
//			TotalPages: aws.Int64(0),
//		},
//		Resources: []*models.Resource{},
//	}
//
//	assert.Equal(t, expected, list.Payload)
//
//	// Unless you specifically ask for them
//	list, err = apiClient.Operations.ListResources(
//		&operations.ListResourcesParams{
//			Deleted:    aws.Bool(true),
//			HTTPClient: httpClient,
//		})
//	require.NoError(t, err)
//	assert.Len(t, list.Payload.Resources, 3)
//}
