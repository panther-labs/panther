package handlers

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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	maxDynamoBackoff = 30 * time.Second
)

// The policy struct stored in Dynamo isn't quite the same as the policy struct returned in the API.
//
// Compliance status is not stored in this table, some string slices are stored as String Sets,
// optional values can be omitted from the table if they are empty,
// and extra fields are added for more efficient filtering.
type tableItem struct {
	AutoRemediationID         string            `json:"autoRemediationId,omitempty"`
	AutoRemediationParameters map[string]string `json:"autoRemediationParameters,omitempty"`
	Body                      string            `json:"body"`
	CreatedAt                 time.Time         `json:"createdAt"`
	CreatedBy                 string            `json:"createdBy"`
	DedupPeriodMinutes        int               `json:"dedupPeriodMinutes,omitempty"`
	Threshold                 int               `json:"threshold,omitempty"`
	Description               string            `json:"description,omitempty"`
	DisplayName               string            `json:"displayName,omitempty"`
	Enabled                   bool              `json:"enabled"`
	ID                        string            `json:"id"`
	LastModified              time.Time         `json:"lastModified"`
	LastModifiedBy            string            `json:"lastModifiedBy"`

	// Lowercase versions of string fields for easy filtering
	LowerDisplayName string   `json:"lowerDisplayName,omitempty"`
	LowerID          string   `json:"lowerId,omitempty"`
	LowerTags        []string `json:"lowerTags,omitempty" dynamodbav:"lowerTags,stringset,omitempty"`

	// For log analysis rules, these are actually log types
	ResourceTypes []string `json:"resourceTypes,omitempty" dynamodbav:"resourceTypes,stringset,omitempty"`

	Mappings     []models.DataModelMapping `json:"mappings,omitempty"`
	OutputIDs    []string                  `json:"outputIds,omitempty" dynamodbav:"outputIds,stringset,omitempty"`
	Reference    string                    `json:"reference,omitempty"`
	Reports      map[string][]string       `json:"reports,omitempty"`
	Runbook      string                    `json:"runbook,omitempty"`
	Severity     compliancemodels.Severity `json:"severity"`
	Suppressions []string                  `json:"suppressions,omitempty" dynamodbav:"suppressions,stringset,omitempty"`
	Tags         []string                  `json:"tags,omitempty" dynamodbav:"tags,stringset,omitempty"`
	Tests        []models.UnitTest         `json:"tests,omitempty"`

	Type      models.DetectionType `json:"type"`
	VersionID string               `json:"versionId,omitempty"`
}

// Add extra internal filtering fields before serializing to Dynamo
func (r *tableItem) addExtraFields() {
	r.LowerDisplayName = strings.ToLower(r.DisplayName)
	r.LowerID = strings.ToLower(r.ID)
	r.LowerTags = lowerSet(r.Tags)
}

// Sort string sets before converting to an external Rule/Policy/Detection model.
func (r *tableItem) normalize() {
	sortCaseInsensitive(r.OutputIDs)
	sortCaseInsensitive(r.ResourceTypes)
	sortCaseInsensitive(r.Suppressions)
	sortCaseInsensitive(r.Tags)
}

// Detection converts a Dynamo row into a Detection external model.
func (r *tableItem) Detection(status compliancemodels.ComplianceStatus) *models.Detection {
	r.normalize()
	result := &models.Detection{
		AutoRemediationID:         r.AutoRemediationID,
		AutoRemediationParameters: r.AutoRemediationParameters,
		ComplianceStatus:          status,
		Suppressions:              r.Suppressions,
		DedupPeriodMinutes:        r.DedupPeriodMinutes,
		Threshold:                 r.Threshold,
		AnalysisType:              r.Type,
		Body:                      r.Body,
		CreatedAt:                 r.CreatedAt,
		CreatedBy:                 r.CreatedBy,
		Description:               r.Description,
		DisplayName:               r.DisplayName,
		Enabled:                   r.Enabled,
		ID:                        r.ID,
		LastModified:              r.LastModified,
		LastModifiedBy:            r.LastModifiedBy,
		OutputIDs:                 r.OutputIDs,
		Reference:                 r.Reference,
		Reports:                   r.Reports,
		Runbook:                   r.Runbook,
		Severity:                  r.Severity,
		Tags:                      r.Tags,
		Tests:                     r.Tests,
		VersionID:                 r.VersionID,
	}
	if r.Type == models.TypePolicy {
		result.ResourceTypes = r.ResourceTypes
	} else if r.Type == models.TypeRule {
		result.LogTypes = r.ResourceTypes
	}

	genericapi.ReplaceMapSliceNils(result)
	return result
}

// Policy converts a Dynamo row into a Policy external model.
func (r *tableItem) Policy(status compliancemodels.ComplianceStatus) *models.Policy {
	r.normalize()
	result := &models.Policy{
		AnalysisType:              models.TypePolicy,
		AutoRemediationID:         r.AutoRemediationID,
		AutoRemediationParameters: r.AutoRemediationParameters,
		ComplianceStatus:          status,
		Body:                      r.Body,
		CreatedAt:                 r.CreatedAt,
		CreatedBy:                 r.CreatedBy,
		Description:               r.Description,
		DisplayName:               r.DisplayName,
		Enabled:                   r.Enabled,
		ID:                        r.ID,
		LastModified:              r.LastModified,
		LastModifiedBy:            r.LastModifiedBy,
		OutputIDs:                 r.OutputIDs,
		Reference:                 r.Reference,
		Reports:                   r.Reports,
		ResourceTypes:             r.ResourceTypes,
		Runbook:                   r.Runbook,
		Severity:                  r.Severity,
		Suppressions:              r.Suppressions,
		Tags:                      r.Tags,
		Tests:                     r.Tests,
		VersionID:                 r.VersionID,
	}
	genericapi.ReplaceMapSliceNils(result)
	return result
}

// Rule converts a Dynamo row into a Rule external model.
func (r *tableItem) Rule() *models.Rule {
	r.normalize()
	result := &models.Rule{
		AnalysisType:       models.TypeRule,
		Body:               r.Body,
		CreatedAt:          r.CreatedAt,
		CreatedBy:          r.CreatedBy,
		DedupPeriodMinutes: r.DedupPeriodMinutes,
		Description:        r.Description,
		DisplayName:        r.DisplayName,
		Enabled:            r.Enabled,
		ID:                 r.ID,
		LastModified:       r.LastModified,
		LastModifiedBy:     r.LastModifiedBy,
		LogTypes:           r.ResourceTypes,
		OutputIDs:          r.OutputIDs,
		Reference:          r.Reference,
		Reports:            r.Reports,
		Runbook:            r.Runbook,
		Severity:           r.Severity,
		Tags:               r.Tags,
		Tests:              r.Tests,
		Threshold:          r.Threshold,
		VersionID:          r.VersionID,
	}
	genericapi.ReplaceMapSliceNils(result)
	return result
}

// Global converts a Dynamo row into a Global external model.
func (r *tableItem) Global() *models.Global {
	r.normalize()
	result := &models.Global{
		Body:           r.Body,
		CreatedAt:      r.CreatedAt,
		CreatedBy:      r.CreatedBy,
		Description:    r.Description,
		ID:             r.ID,
		LastModified:   r.LastModified,
		LastModifiedBy: r.LastModifiedBy,
		Tags:           r.Tags,
		VersionID:      r.VersionID,
	}
	genericapi.ReplaceMapSliceNils(result)
	return result
}

// DataModel converts a Dynamo row into a DataModel external model.
func (r *tableItem) DataModel() *models.DataModel {
	r.normalize()
	result := &models.DataModel{
		Body:           r.Body,
		CreatedAt:      r.CreatedAt,
		CreatedBy:      r.CreatedBy,
		Description:    r.Description,
		DisplayName:    r.DisplayName,
		Enabled:        r.Enabled,
		ID:             r.ID,
		LastModified:   r.LastModified,
		LastModifiedBy: r.LastModifiedBy,
		LogTypes:       r.ResourceTypes,
		Mappings:       r.Mappings,
		VersionID:      r.VersionID,
	}
	genericapi.ReplaceMapSliceNils(result)
	return result
}

func tableKey(policyID string) map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"id": {S: &policyID},
	}
}

// Batch delete multiple entries from the Dynamo table.
func dynamoBatchDelete(input *models.DeletePoliciesInput) error {
	deleteRequests := make([]*dynamodb.WriteRequest, len(input.Entries))
	for i, entry := range input.Entries {
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
func dynamoGet(policyID string, consistentRead bool) (*tableItem, error) {
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

type stringSet []string

// Marshal string slice as a Dynamo StringSet instead of a List
func (s stringSet) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	av.SS = make([]*string, 0, len(s))
	for _, pattern := range s {
		av.SS = append(av.SS, aws.String(pattern))
	}
	return nil
}

// Add suppressions to an existing policy, returning the updated list of policies.
func addSuppressions(policyIDs []string, patterns []string) ([]*tableItem, error) {
	update := expression.Add(expression.Name("suppressions"), expression.Value(stringSet(patterns)))
	condition := expression.AttributeExists(expression.Name("id"))
	expr, err := expression.NewBuilder().WithUpdate(update).WithCondition(condition).Build()
	if err != nil {
		zap.L().Error("failed to build update expression", zap.Error(err))
		return nil, err
	}
	result := make([]*tableItem, 0, len(policyIDs))

	// Dynamo does not support batch update - proceed sequentially
	for _, policyID := range policyIDs {
		zap.L().Info("updating policy suppressions", zap.String("policyId", policyID))
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
				zap.L().Warn("policy not found", zap.String("policyId", policyID))
				continue
			}
			zap.L().Error("dynamoClient.UpdateItem failed", zap.Error(err))
			return nil, err
		}

		var item tableItem
		if err := dynamodbattribute.UnmarshalMap(response.Attributes, &item); err != nil {
			zap.L().Error("failed to unmarshal updated policy", zap.Error(err))
			return nil, err
		}
		result = append(result, &item)
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
func scanPages(input *dynamodb.ScanInput, handler func(tableItem) error) error {
	var handlerErr, unmarshalErr error

	err := dynamoClient.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		var items []tableItem
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

// Build dynamo scan input for list operations
func buildScanInput(itemTypes []models.DetectionType, fields []string, filters ...expression.ConditionBuilder) (
	*dynamodb.ScanInput, error) {

	var masterFilter expression.ConditionBuilder
	for i, itemType := range itemTypes {
		if i == 0 {
			masterFilter = expression.Equal(expression.Name("type"), expression.Value(itemType))
			continue
		}
		masterFilter = expression.Or(masterFilter, expression.Equal(expression.Name("type"), expression.Value(itemType)))
	}

	for _, filter := range filters {
		masterFilter = masterFilter.And(filter)
	}
	builder := expression.NewBuilder().WithFilter(masterFilter)

	if len(fields) > 0 {
		projection := expression.NamesList(expression.Name(dynamoColumn(fields[0])))
		for _, field := range fields[1:] {
			projection = projection.AddNames(expression.Name(dynamoColumn(field)))
		}
		builder = builder.WithProjection(projection)
	}

	expr, err := builder.Build()
	if err != nil {
		zap.L().Error("unable to build dynamodb scan expression", zap.Error(err))
		return nil, err
	}

	result := dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &env.Table,
	}
	zap.L().Debug("built dynamo scan input", zap.Any("scanInput", result))
	return &result, nil
}

// When the caller selects a list of fields to return in the response,
// they may not exactly match the Dynamo column name.
func dynamoColumn(field string) string {
	if field == "logTypes" {
		return "resourceTypes"
	}
	return field
}
