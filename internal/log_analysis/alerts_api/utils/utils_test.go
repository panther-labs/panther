package utils

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/stretchr/testify/require"

	alertmodels "github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/testutils"
)

var timeInTest = time.Now()

func TestAlertItemToSummary(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}

	alertItem := table.AlertItem{
		RuleID:            "ruleId",
		AlertID:           "alertId",
		Status:            "",
		UpdateTime:        timeInTest,
		CreationTime:      timeInTest,
		Severity:          "INFO",
		DedupString:       "dedupString",
		LogTypes:          []string{"AWS.CloudTrail"},
		ResourceTypes:     []string{"AWS.ResourceType"},
		ResourceID:        "resourceId",
		EventCount:        100,
		RuleVersion:       "ruleVersion",
		RuleDisplayName:   aws.String("ruleDisplayName"),
		Title:             "title",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: timeInTest,
		DeliveryResponses: []*alertmodels.DeliveryResponse{},
	}

	alertRule := models.Rule{
		CreatedAt: time.Now().UTC(),
		// Description:        "description",
		DisplayName:  "ruleDisplayName",
		Enabled:      true,
		ID:           "ruleId",
		LastModified: time.Now().UTC(),
		LogTypes:     []string{"AWS.CloudTrail"},
		OutputIDs:    []string{"destination-1", "destination-2"},
		Severity:     "INFO",
		VersionID:    "ruleVersion",
	}

	expectedAlertSummary := alertmodels.AlertSummary{
		RuleID:            aws.String("ruleId"),
		RuleVersion:       aws.String("ruleVersion"),
		Type:              "RULE",
		RuleDisplayName:   aws.String("ruleDisplayName"),
		AlertID:           "alertId",
		Status:            "OPEN",
		UpdateTime:        aws.Time(timeInTest),
		CreationTime:      aws.Time(timeInTest),
		Severity:          aws.String("INFO"),
		DedupString:       aws.String("dedupString"),
		EventsMatched:     aws.Int(100),
		Title:             aws.String("title"),
		LogTypes:          []string{"AWS.CloudTrail"},
		ResourceTypes:     []string{"AWS.ResourceType"},
		ResourceID:        "resourceId",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: timeInTest,
		DeliveryResponses: []*alertmodels.DeliveryResponse{},
	}

	item, err := dynamodbattribute.MarshalMap(expectedAlertSummary)
	require.NoError(t, err)

	mockDdbClient.On("GetItem", alertItem, nil).Return(item)
	result := AlertItemToSummary(&alertItem, &alertRule)
	require.Equal(t, expectedAlertSummary, *result)
}

func TestAlertItemToSummaryHavingGeneratedFields(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}

	alertItem := table.AlertItem{
		RuleID:            "ruleId",
		AlertID:           "alertId",
		Status:            "",
		UpdateTime:        timeInTest,
		CreationTime:      timeInTest,
		Severity:          "INFO",
		DedupString:       "dedupString",
		LogTypes:          []string{"AWS.CloudTrail"},
		ResourceTypes:     []string{"AWS.ResourceType"},
		ResourceID:        "resourceId",
		EventCount:        100,
		RuleVersion:       "ruleVersion",
		RuleDisplayName:   aws.String("ruleDisplayName"),
		Title:             "title",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: timeInTest,
		DeliveryResponses: []*alertmodels.DeliveryResponse{},
		Description:       aws.String("description"),
		Reference:         aws.String("reference"),
		Runbook:           aws.String("runbook"),
	}

	alertRule := models.Rule{
		CreatedAt:    time.Now().UTC(),
		DisplayName:  "ruleDisplayName",
		Enabled:      true,
		ID:           "ruleId",
		LastModified: time.Now().UTC(),
		LogTypes:     []string{"AWS.CloudTrail"},
		OutputIDs:    []string{"destination-1", "destination-2"},
		Severity:     "INFO",
		VersionID:    "ruleVersion",
	}

	expectedAlertSummary := alertmodels.AlertSummary{
		RuleID:            aws.String("ruleId"),
		RuleVersion:       aws.String("ruleVersion"),
		Type:              "RULE",
		RuleDisplayName:   aws.String("ruleDisplayName"),
		AlertID:           "alertId",
		Status:            "OPEN",
		UpdateTime:        aws.Time(timeInTest),
		CreationTime:      aws.Time(timeInTest),
		Severity:          aws.String("INFO"),
		DedupString:       aws.String("dedupString"),
		EventsMatched:     aws.Int(100),
		Title:             aws.String("title"),
		LogTypes:          []string{"AWS.CloudTrail"},
		ResourceTypes:     []string{"AWS.ResourceType"},
		ResourceID:        "resourceId",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: timeInTest,
		DeliveryResponses: []*alertmodels.DeliveryResponse{},
		Description:       "description",
		Reference:         "reference",
		Runbook:           "runbook",
	}

	item, err := dynamodbattribute.MarshalMap(expectedAlertSummary)
	require.NoError(t, err)

	mockDdbClient.On("GetItem", alertItem, nil).Return(item)
	result := AlertItemToSummary(&alertItem, &alertRule)
	require.Equal(t, expectedAlertSummary, *result)
}

func TestAlertItemToSummaryMissingGeneratedFields(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}

	alertItem := table.AlertItem{
		RuleID:            "ruleId",
		AlertID:           "alertId",
		Status:            "",
		UpdateTime:        timeInTest,
		CreationTime:      timeInTest,
		Severity:          "INFO",
		DedupString:       "dedupString",
		LogTypes:          []string{"AWS.CloudTrail"},
		ResourceTypes:     []string{"AWS.ResourceType"},
		ResourceID:        "resourceId",
		EventCount:        100,
		RuleVersion:       "ruleVersion",
		RuleDisplayName:   aws.String("ruleDisplayName"),
		Title:             "title",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: timeInTest,
		DeliveryResponses: []*alertmodels.DeliveryResponse{},
	}

	alertRule := models.Rule{
		CreatedAt:    time.Now().UTC(),
		DisplayName:  "ruleDisplayName",
		Enabled:      true,
		ID:           "ruleId",
		LastModified: time.Now().UTC(),
		LogTypes:     []string{"AWS.CloudTrail"},
		OutputIDs:    []string{"destination-1", "destination-2"},
		Severity:     "INFO",
		VersionID:    "ruleVersion",
		Description:  "ruleDescription",
		Reference:    "ruleReference",
		Runbook:      "ruleRunbook",
	}

	expectedAlertSummary := alertmodels.AlertSummary{
		RuleID:            aws.String("ruleId"),
		RuleVersion:       aws.String("ruleVersion"),
		Type:              "RULE",
		RuleDisplayName:   aws.String("ruleDisplayName"),
		AlertID:           "alertId",
		Status:            "OPEN",
		UpdateTime:        aws.Time(timeInTest),
		CreationTime:      aws.Time(timeInTest),
		Severity:          aws.String("INFO"),
		DedupString:       aws.String("dedupString"),
		EventsMatched:     aws.Int(100),
		Title:             aws.String("title"),
		LogTypes:          []string{"AWS.CloudTrail"},
		ResourceTypes:     []string{"AWS.ResourceType"},
		ResourceID:        "resourceId",
		LastUpdatedBy:     "userId",
		LastUpdatedByTime: timeInTest,
		DeliveryResponses: []*alertmodels.DeliveryResponse{},
		Description:       "ruleDescription",
		Reference:         "ruleReference",
		Runbook:           "ruleRunbook",
	}

	item, err := dynamodbattribute.MarshalMap(expectedAlertSummary)
	require.NoError(t, err)

	mockDdbClient.On("GetItem", alertItem, nil).Return(item)
	result := AlertItemToSummary(&alertItem, &alertRule)
	require.Equal(t, expectedAlertSummary, *result)
}
