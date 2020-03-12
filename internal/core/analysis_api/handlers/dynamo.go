package handlers

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	typePolicy       = string(models.AnalysisTypePOLICY)
	typeRule         = string(models.AnalysisTypeRULE)
	maxDynamoBackoff = 30 * time.Second
)

// The policy struct stored in Dynamo isn't quite the same as the policy struct returned in the API.
//
// Compliance status is not stored in this table, some string slices are stored as String Sets,
// optional values can be omitted from the table if they are empty,
// and extra fields are added for more efficient filtering.
type tableItem struct {
	AutoRemediationID         models.AutoRemediationID         `json:"autoRemediationId,omitempty"`
	AutoRemediationParameters models.AutoRemediationParameters `json:"autoRemediationParameters,omitempty"`
	Body                      models.Body                      `json:"body"`
	CreatedAt                 models.ModifyTime                `json:"createdAt"`
	CreatedBy                 models.UserID                    `json:"createdBy"`
	Description               models.Description               `json:"description,omitempty"`
	DisplayName               models.DisplayName               `json:"displayName,omitempty"`
	Enabled                   models.Enabled                   `json:"enabled"`
	ID                        models.ID                        `json:"id"`
	LastModified              models.ModifyTime                `json:"lastModified"`
	LastModifiedBy            models.UserID                    `json:"lastModifiedBy"`
	Reference                 models.Reference                 `json:"reference,omitempty"`
	ResourceTypes             models.TypeSet                   `json:"resourceTypes,omitempty" dynamodbav:"resourceTypes,stringset,omitempty"`
	Runbook                   models.Runbook                   `json:"runbook,omitempty"`
	Severity                  models.Severity                  `json:"severity"`
	Suppressions              models.Suppressions              `json:"suppressions,omitempty" dynamodbav:"suppressions,stringset,omitempty"`
	Tags                      models.Tags                      `json:"tags,omitempty" dynamodbav:"tags,stringset,omitempty"`
	Tests                     []*models.UnitTest               `json:"tests,omitempty"`
	VersionID                 models.VersionID                 `json:"versionId,omitempty"`
	DedupPeriodMinutes        models.DedupPeriodMinutes        `json:"dedupPeriodMinutes,omitempty"`

	// Logic type (policy or rule)
	Type string `json:"type"`

	// Lowercase versions of string fields for easy filtering
	LowerDisplayName string   `json:"lowerDisplayName,omitempty"`
	LowerID          string   `json:"lowerId,omitempty"`
	LowerTags        []string `json:"lowerTags,omitempty" dynamodbav:"lowerTags,stringset,omitempty"`
}

// Add extra internal filtering fields before serializing to Dynamo
func (r *tableItem) addExtraFields() {
	r.LowerDisplayName = strings.ToLower(string(r.DisplayName))
	r.LowerID = strings.ToLower(string(r.ID))
	r.LowerTags = lowerSet(r.Tags)
}

// Sort string sets before converting to an external Rule/Policy model.
func (r *tableItem) normalize() {
	sortCaseInsensitive(r.ResourceTypes)
	sortCaseInsensitive(r.Suppressions)
	sortCaseInsensitive(r.Tags)
}

// Policy converts a Dynamo row into a Policy external model.
func (r *tableItem) Policy(status models.ComplianceStatus) *models.Policy {
	r.normalize()
	result := &models.Policy{
		AutoRemediationID:         r.AutoRemediationID,
		AutoRemediationParameters: r.AutoRemediationParameters,
		Body:                      r.Body,
		ComplianceStatus:          status,
		CreatedAt:                 r.CreatedAt,
		CreatedBy:                 r.CreatedBy,
		Description:               r.Description,
		DisplayName:               r.DisplayName,
		Enabled:                   r.Enabled,
		ID:                        r.ID,
		LastModified:              r.LastModified,
		LastModifiedBy:            r.LastModifiedBy,
		Reference:                 r.Reference,
		ResourceTypes:             r.ResourceTypes,
		Runbook:                   r.Runbook,
		Severity:                  r.Severity,
		Suppressions:              r.Suppressions,
		Tags:                      r.Tags,
		Tests:                     r.Tests,
		VersionID:                 r.VersionID,
	}
	gatewayapi.ReplaceMapSliceNils(result)
	return result
}

// PolicySummary converts a Dynamo row into a PolicySummary external model.
func (r *tableItem) PolicySummary(status models.ComplianceStatus) *models.PolicySummary {
	r.normalize()
	result := &models.PolicySummary{
		AutoRemediationID:         r.AutoRemediationID,
		AutoRemediationParameters: r.AutoRemediationParameters,
		ComplianceStatus:          status,
		DisplayName:               r.DisplayName,
		Enabled:                   r.Enabled,
		ID:                        r.ID,
		LastModified:              r.LastModified,
		ResourceTypes:             r.ResourceTypes,
		Severity:                  r.Severity,
		Suppressions:              r.Suppressions,
		Tags:                      r.Tags,
	}
	gatewayapi.ReplaceMapSliceNils(result)
	return result
}

// Rule converts a Dynamo row into a Rule external model.
func (r *tableItem) Rule() *models.Rule {
	r.normalize()
	result := &models.Rule{
		Body:               r.Body,
		CreatedAt:          r.CreatedAt,
		CreatedBy:          r.CreatedBy,
		Description:        r.Description,
		DisplayName:        r.DisplayName,
		Enabled:            r.Enabled,
		ID:                 r.ID,
		LastModified:       r.LastModified,
		LastModifiedBy:     r.LastModifiedBy,
		LogTypes:           r.ResourceTypes,
		Reference:          r.Reference,
		Runbook:            r.Runbook,
		Severity:           r.Severity,
		Tags:               r.Tags,
		Tests:              r.Tests,
		VersionID:          r.VersionID,
		DedupPeriodMinutes: r.DedupPeriodMinutes,
	}
	gatewayapi.ReplaceMapSliceNils(result)
	return result
}

func tableKey(policyID models.ID) map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"id": {S: aws.String(string(policyID))},
	}
}

// Batch delete multiple policies from the Dynamo table.
func dynamoBatchDelete(input *models.DeletePolicies) error {
	deleteRequests := make([]*dynamodb.WriteRequest, len(input.Policies))
	for i, entry := range input.Policies {
		deleteRequests[i] = &dynamodb.WriteRequest{
			DeleteRequest: &dynamodb.DeleteRequest{Key: tableKey(entry.ID)},
		}
	}

	batchInput := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{env.Table: deleteRequests},
	}
	if err := dynamodbbatch.BatchWriteItem(dynamoClient, maxDynamoBackoff, batchInput); err != nil {
		zap.L().Error("dynamodbbatch.BatchWriteItem (delete) failed", zap.Error(err))
		return err
	}

	return nil
}

// Load a policy/rule from the Dynamo table.
//
// Returns (nil, nil) if the item doesn't exist.
func dynamoGet(policyID models.ID, consistentRead bool) (*tableItem, error) {
	response, err := dynamoClient.GetItem(&dynamodb.GetItemInput{
		ConsistentRead: &consistentRead,
		Key:            tableKey(policyID),
		TableName:      &env.Table,
	})
	if err != nil {
		zap.L().Error("dynamoClient.GetItem failed", zap.Error(err))
		return nil, err
	}

	if len(response.Item) == 0 {
		return nil, nil
	}

	var policy tableItem
	if err = dynamodbattribute.UnmarshalMap(response.Item, &policy); err != nil {
		zap.L().Error("dynamodbattribute.UnmarshalMap failed", zap.Error(err))
		return nil, err
	}

	return &policy, nil
}

type suppressSet models.Suppressions

// Marshal string slice as a Dynamo StringSet instead of a List
func (s suppressSet) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	av.SS = make([]*string, 0, len(s))
	for _, pattern := range s {
		av.SS = append(av.SS, aws.String(pattern))
	}
	return nil
}

// Add suppressions to an existing policy, returning the updated list of policies.
func addSuppressions(policyIDs []models.ID, patterns models.Suppressions) ([]*tableItem, error) {
	update := expression.Add(expression.Name("suppressions"), expression.Value(suppressSet(patterns)))
	condition := expression.AttributeExists(expression.Name("id"))
	expr, err := expression.NewBuilder().WithUpdate(update).WithCondition(condition).Build()
	if err != nil {
		zap.L().Error("failed to build update expression", zap.Error(err))
		return nil, err
	}
	result := make([]*tableItem, 0, len(policyIDs))

	// Dynamo does not support batch update - proceed sequentially
	for _, policyID := range policyIDs {
		zap.L().Info("updating policy suppressions",
			zap.String("policyId", string(policyID)))
		response, err := dynamoClient.UpdateItem(&dynamodb.UpdateItemInput{
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
			Key:                       tableKey(policyID),
			ReturnValues:              aws.String("ALL_NEW"),
			TableName:                 &env.Table,
			UpdateExpression:          expr.Update(),
		})

		if err != nil {
			aerr, ok := err.(awserr.Error)
			if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
				zap.L().Warn("policy not found",
					zap.String("policyId", string(policyID)))
				continue
			}
			zap.L().Error("dynamoClient.UpdateItem failed", zap.Error(err))
			return nil, err
		}

		item := new(tableItem)
		if err := dynamodbattribute.UnmarshalMap(response.Attributes, item); err != nil {
			zap.L().Error("failed to unmarshal updated policy", zap.Error(err))
			return nil, err
		}
		result = append(result, item)
	}

	return result, nil
}

// Write a single policy to Dynamo.
func dynamoPut(policy *tableItem) error {
	policy.addExtraFields()
	body, err := dynamodbattribute.MarshalMap(policy)
	if err != nil {
		zap.L().Error("dynamodbattribute.MarshalMap failed", zap.Error(err))
		return err
	}

	if _, err = dynamoClient.PutItem(&dynamodb.PutItemInput{Item: body, TableName: &env.Table}); err != nil {
		zap.L().Error("dynamoClient.PutItem failed", zap.Error(err))
		return err
	}

	return nil
}

// Wrapper around dynamoClient.ScanPages that accepts a handler function to process each item.
func scanPages(input *dynamodb.ScanInput, handler func(*tableItem) error) error {
	var handlerErr, unmarshalErr error

	err := dynamoClient.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		var items []*tableItem
		if unmarshalErr = dynamodbattribute.UnmarshalListOfMaps(page.Items, &items); unmarshalErr != nil {
			return false // stop paginating
		}

		for _, entry := range items {
			if handlerErr = handler(entry); handlerErr != nil {
				return false // stop paginating
			}
		}

		return true // keep paging
	})

	if handlerErr != nil {
		zap.L().Error("query item handler failed", zap.Error(handlerErr))
		return handlerErr
	}

	if unmarshalErr != nil {
		zap.L().Error("dynamodbattribute.UnmarshalListOfMaps failed", zap.Error(unmarshalErr))
		return unmarshalErr
	}

	if err != nil {
		zap.L().Error("dynamoClient.QueryPages failed", zap.Error(err))
		return err
	}

	return nil
}
