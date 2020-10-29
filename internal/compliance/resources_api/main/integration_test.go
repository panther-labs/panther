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
	"time"

	"github.com/aws/aws-sdk-go/aws"
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

	bucket = models.Resource{
		Attributes:      map[string]interface{}{"Panther": "Labs"},
		ID:              "arn:aws:s3:::my-bucket",
		IntegrationID:   "df6652ff-22d7-4c6a-a9ec-3fe50fadbbbf",
		IntegrationType: "aws",
		Type:            "AWS.S3.Bucket",
	}
	key = models.Resource{
		Attributes:      map[string]interface{}{"Panther": "Labs"},
		ID:              "arn:aws:kms:us-west-2:111111111111:key/09510b31-48bf-464f-8c16-c5669e414c4a",
		IntegrationID:   "df6652ff-22d7-4c6a-a9ec-3fe50fadbbbf",
		IntegrationType: "aws",
		Type:            "AWS.KMS.Key",
	}
	queue = models.Resource{
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
		t.Run("AddEmpty", addEmpty)
		t.Run("AddSuccess", addSuccess)
	})

	t.Run("GetResource", func(t *testing.T) {
		t.Run("GetInvalid", getInvalid)
		t.Run("GetNotFound", getNotFound)
		t.Run("GetSuccess", getSuccess)
	})
	if t.Failed() {
		return
	}

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
	t.Parallel()
	input := models.LambdaInput{
		AddResources: &models.AddResourcesInput{
			Resources: []models.AddResourceEntry{
				{
					// missing attributes
					ID:              bucket.ID,
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
		"panther-resources-api: InvalidInputError: Attributes invalid, failed to satisfy the condition: required",
		err.Error())
}

func addSuccess(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	input := models.LambdaInput{
		GetResource: &models.GetResourceInput{},
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)
	assert.Equal(t,
		"panther-resources-api: InvalidInputError: ID invalid, failed to satisfy the condition: required",
		err.Error())
}

func getNotFound(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetResource: &models.GetResourceInput{ID: "arn:aws:s3:::no-such-bucket"},
	}

	statusCode, err := apiClient.Invoke(&input, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, statusCode)
}

// Compliance status and last modified time should be non-empty, but exact values don't matter
func resetUnpredictableFields(t *testing.T, r *models.Resource) {
	assert.NotEmpty(t, r.ComplianceStatus)
	assert.NotEmpty(t, r.LastModified)

	r.ComplianceStatus = ""
	r.LastModified = time.Time{}
}

func getSuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetResource: &models.GetResourceInput{ID: bucket.ID},
	}
	var result models.Resource
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	resetUnpredictableFields(t, &result)
	require.Equal(t, bucket, result)
}

func listAll(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListResources: &models.ListResourcesInput{},
	}
	var result models.ListResourcesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListResourcesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 1,
		},
		Resources: []models.Resource{
			// resources will be in alphabetical order by their ID
			// attributes are not included in the list operation
			{
				Deleted:         false,
				ID:              key.ID,
				IntegrationID:   key.IntegrationID,
				IntegrationType: key.IntegrationType,
				Type:            key.Type,
			},
			{
				Deleted:         false,
				ID:              bucket.ID,
				IntegrationID:   bucket.IntegrationID,
				IntegrationType: bucket.IntegrationType,
				Type:            bucket.Type,
			},
			{
				Deleted:         false,
				ID:              queue.ID,
				IntegrationID:   queue.IntegrationID,
				IntegrationType: queue.IntegrationType,
				Type:            queue.Type,
			},
		},
	}

	// compliance status and last modified time are unpredictable
	for i := range result.Resources {
		resetUnpredictableFields(t, &result.Resources[i])
	}
	assert.Equal(t, expected, result)
}

func listPaged(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListResources: &models.ListResourcesInput{
			PageSize: 1,
			SortDir:  "descending", // sort by ID descending
		},
	}
	var result models.ListResourcesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListResourcesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 3,
			TotalPages: 3,
		},
		Resources: []models.Resource{
			{
				Deleted:         false,
				ID:              queue.ID,
				IntegrationID:   queue.IntegrationID,
				IntegrationType: queue.IntegrationType,
				Type:            queue.Type,
			},
		},
	}
	require.Len(t, result.Resources, 1)
	resetUnpredictableFields(t, &result.Resources[0])
	assert.Equal(t, expected, result)

	// Page 2
	input = models.LambdaInput{
		ListResources: &models.ListResourcesInput{
			Page:     2,
			PageSize: 1,
			SortDir:  "descending",
		},
	}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected = models.ListResourcesOutput{
		Paging: models.Paging{
			ThisPage:   2,
			TotalItems: 3,
			TotalPages: 3,
		},
		Resources: []models.Resource{
			{
				Deleted:         false,
				ID:              bucket.ID,
				IntegrationID:   bucket.IntegrationID,
				IntegrationType: bucket.IntegrationType,
				Type:            bucket.Type,
			},
		},
	}
	require.Len(t, result.Resources, 1)
	resetUnpredictableFields(t, &result.Resources[0])
	assert.Equal(t, expected, result)

	// Page 3
	input = models.LambdaInput{
		ListResources: &models.ListResourcesInput{
			Page:     3,
			PageSize: 1,
			SortDir:  "descending",
		},
	}
	statusCode, err = apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected = models.ListResourcesOutput{
		Paging: models.Paging{
			ThisPage:   3,
			TotalItems: 3,
			TotalPages: 3,
		},
		Resources: []models.Resource{
			{
				Deleted:         false,
				ID:              key.ID,
				IntegrationID:   key.IntegrationID,
				IntegrationType: key.IntegrationType,
				Type:            key.Type,
			},
		},
	}
	require.Len(t, result.Resources, 1)
	resetUnpredictableFields(t, &result.Resources[0])
	assert.Equal(t, expected, result)
}

func listFiltered(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListResources: &models.ListResourcesInput{
			Deleted:         aws.Bool(false),
			Fields:          []string{"attributes", "id", "type"},
			IDContains:      "MY", // queue + bucket
			IntegrationID:   bucket.IntegrationID,
			IntegrationType: bucket.IntegrationType,
			Types:           []string{bucket.Type},
		},
	}
	var result models.ListResourcesOutput
	statusCode, err := apiClient.Invoke(&input, &result)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListResourcesOutput{
		Paging: models.Paging{
			ThisPage:   1,
			TotalItems: 1,
			TotalPages: 1,
		},
		Resources: []models.Resource{
			{
				Attributes: bucket.Attributes,
				ID:         bucket.ID,
				Type:       bucket.Type,
			},
		},
	}
	assert.Equal(t, expected, result)
}

func deleteInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DeleteResources: &models.DeleteResourcesInput{
			Resources: []models.DeleteEntry{},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, statusCode)

	assert.Equal(t,
		"panther-resources-api: InvalidInputError: Resources invalid, failed to satisfy the condition: min=1",
		err.Error())
}

// No error is returned if deletes are requested for resources that don't exist
func deleteNotFound(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DeleteResources: &models.DeleteResourcesInput{
			Resources: []models.DeleteEntry{
				{ID: "no-such-resource"},
			},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
}

func deleteSuccess(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		DeleteResources: &models.DeleteResourcesInput{
			Resources: []models.DeleteEntry{
				{ID: bucket.ID},
				{ID: key.ID},
				{ID: queue.ID},
			},
		},
	}
	statusCode, err := apiClient.Invoke(&input, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	// Deleted resources should not show up for a standard list
	input = models.LambdaInput{
		ListResources: &models.ListResourcesInput{
			Deleted: aws.Bool(false),
		},
	}
	var listResult models.ListResourcesOutput
	statusCode, err = apiClient.Invoke(&input, &listResult)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	expected := models.ListResourcesOutput{
		Resources: []models.Resource{},
	}
	assert.Equal(t, expected, listResult)

	// Unless you specifically ask for them
	input = models.LambdaInput{
		ListResources: &models.ListResourcesInput{
			Deleted: aws.Bool(true),
		},
	}
	statusCode, err = apiClient.Invoke(&input, &listResult)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Len(t, listResult.Resources, 3)
}
