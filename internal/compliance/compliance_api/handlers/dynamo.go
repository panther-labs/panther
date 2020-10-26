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
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

type policyMap map[string]*models.PolicySummary
type resourceMap map[string]*models.ResourceSummary

var (
	awsSession                             = session.Must(session.NewSession())
	dynamoClient dynamodbiface.DynamoDBAPI = dynamodb.New(awsSession)
)

// Build the table key in the format Dynamo expects
func tableKey(resourceID string, policyID string) map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"resourceId": {S: &resourceID},
		"policyId":   {S: &policyID},
	}
}

// Wrapper around dynamoClient.QueryPages that accepts a handler function to process each item.
func queryPages(input *dynamodb.QueryInput, handler func(*models.ComplianceEntry) error) error {
	var innerErr error
	err := dynamoClient.QueryPages(input, func(page *dynamodb.QueryOutput, lastPage bool) bool {
		if innerErr = handleItems(page.Items, handler); innerErr != nil {
			zap.L().Error("query handler failed", zap.Error(innerErr))
			return false // stop paging
		}
		return true
	})

	if innerErr != nil {
		return innerErr
	}
	if err != nil {
		zap.L().Error("dynamoClient.QueryPages failed", zap.Error(err))
		return err
	}

	return nil
}

// Wrapper around dynamoClient.ScanPages that accepts a handler function to process each item.
func scanPages(input *dynamodb.ScanInput, handler func(*models.ComplianceEntry) error) error {
	var innerErr error
	err := dynamoClient.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		if innerErr = handleItems(page.Items, handler); innerErr != nil {
			zap.L().Error("scan handler failed", zap.Error(innerErr))
			return false // stop paging
		}
		return true
	})

	if innerErr != nil {
		return innerErr
	}
	if err != nil {
		return fmt.Errorf("dynamoClient.ScanPages failed: %s", err)
	}

	return nil
}

// Page handler shared by queryPages and ScanPages
func handleItems(items []map[string]*dynamodb.AttributeValue, handler func(*models.ComplianceEntry) error) error {
	var statusPage []*models.ComplianceEntry
	if err := dynamodbattribute.UnmarshalListOfMaps(items, &statusPage); err != nil {
		return err
	}

	for _, entry := range statusPage {
		if err := handler(entry); err != nil {
			return err
		}
	}

	return nil
}

// Scan Dynamo table to group everything by policyID and/or resourceID
func scanGroupByID(
	input *dynamodb.ScanInput,
	includePolicies bool,
	includeResources bool,
) (policyMap, resourceMap, error) {

	var policies policyMap
	var resources resourceMap
	if includePolicies {
		policies = make(policyMap, 200)
	}
	if includeResources {
		resources = make(resourceMap, 1000)
	}

	// Summarize every policy and resource in the organization.
	err := scanPages(input, func(item *models.ComplianceEntry) error {
		// Update policies
		if includePolicies {
			policy, ok := policies[item.PolicyID]
			if !ok {
				policy = &models.PolicySummary{
					ID:       item.PolicyID,
					Severity: item.PolicySeverity,
				}
				policies[item.PolicyID] = policy
			}
			updateStatusCount(&policy.Count, item.Status)
		}

		// Update resources
		if includeResources {
			resource, ok := resources[item.ResourceID]
			if !ok {
				resource = &models.ResourceSummary{
					ID:   item.ResourceID,
					Type: item.ResourceType,
				}
				resources[item.ResourceID] = resource
			}
			updateStatusCountBySeverity(&resource.Count, item.PolicySeverity, item.Status)
		}

		return nil
	})

	return policies, resources, err
}
