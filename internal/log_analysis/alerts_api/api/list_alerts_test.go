package api

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
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	rulemodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

var (
	timeInTest = time.Now()
	alertItems = []*table.AlertItem{
		{
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
			DeliveryResponses: []*models.DeliveryResponse{},
			Description:       aws.String("description"),
			Reference:         aws.String("reference"),
			Runbook:           aws.String("runbook"),
		},
	}

	expectedAlertSummary = []*models.AlertSummary{
		{
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
			DeliveryResponses: []*models.DeliveryResponse{},
			Description:       "description",
			Reference:         "reference",
			Runbook:           "runbook",
		},
	}
)

func TestListAlertsForRule(t *testing.T) {
	api := initTestAPI()

	input := &models.ListAlertsInput{
		RuleID:            aws.String("ruleId"),
		Status:            []string{models.TriagedStatus},
		PageSize:          aws.Int(10),
		ExclusiveStartKey: aws.String("startKey"),
		Severity:          []string{"INFO"},
	}

	api.mockTable.On("ListAll", input).
		Return(alertItems, aws.String("lastKey"), nil)
	api.mockRuleCache.On("Get", "ruleId", "ruleVersion").Return(&rulemodels.Rule{}, nil).Once()

	result, err := api.ListAlerts(input)
	assert.NoError(t, err)

	assert.Equal(t, &models.ListAlertsOutput{
		Alerts:           expectedAlertSummary,
		LastEvaluatedKey: aws.String("lastKey"),
	}, result)
	api.AssertExpectations(t)
}

func TestListAllAlerts(t *testing.T) {
	api := initTestAPI()

	input := &models.ListAlertsInput{
		PageSize:          aws.Int(10),
		ExclusiveStartKey: aws.String("startKey"),
		Status:            []string{models.TriagedStatus},
		Severity:          []string{"INFO"},
		NameContains:      aws.String("title"),
		EventCountMin:     aws.Int(0),
		EventCountMax:     aws.Int(100),
		CreatedAtAfter:    aws.Time(time.Now()),
		CreatedAtBefore:   aws.Time(time.Now()),
		SortDir:           aws.String("ascending"),
	}
	api.mockTable.On("ListAll", input).Return(alertItems, aws.String("lastKey"), nil)

	api.mockRuleCache.On("Get", "ruleId", "ruleVersion").Return(&rulemodels.Rule{}, nil)

	result, err := api.ListAlerts(input)
	assert.NoError(t, err)
	assert.Equal(t, &models.ListAlertsOutput{
		Alerts:           expectedAlertSummary,
		LastEvaluatedKey: aws.String("lastKey"),
	}, result)
	api.AssertExpectations(t)
}

// Verifies backwards compatibility
// Verifies that API returns correct results when alert title is not specified
func TestListAllAlertsWithoutTitle(t *testing.T) {
	t.Parallel()
	api := initTestAPI()

	alertItems := []*table.AlertItem{
		{
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
			LastUpdatedBy:     "userId",
			LastUpdatedByTime: timeInTest,
			Description:       aws.String("description"),
			Reference:         aws.String("reference"),
			Runbook:           aws.String("runbook"),
		},
		{ // Alert with Display Name for rule
			RuleID:            "ruleId",
			AlertID:           "alertId",
			Status:            "TRIAGED",
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
			LastUpdatedBy:     "userId",
			LastUpdatedByTime: timeInTest,
			Description:       aws.String("description"),
			Reference:         aws.String("reference"),
			Runbook:           aws.String("runbook"),
		},
	}

	expectedAlertSummary := []*models.AlertSummary{
		{
			RuleID:            aws.String("ruleId"),
			RuleVersion:       aws.String("ruleVersion"),
			AlertID:           "alertId",
			Status:            "OPEN",
			Type:              "RULE",
			UpdateTime:        aws.Time(timeInTest),
			CreationTime:      aws.Time(timeInTest),
			Severity:          aws.String("INFO"),
			DedupString:       aws.String("dedupString"),
			EventsMatched:     aws.Int(100),
			Title:             aws.String("ruleId"),
			LogTypes:          []string{"AWS.CloudTrail"},
			ResourceTypes:     []string{"AWS.ResourceType"},
			ResourceID:        "resourceId",
			LastUpdatedBy:     "userId",
			LastUpdatedByTime: timeInTest,
			DeliveryResponses: []*models.DeliveryResponse{},
			Description:       "description",
			Reference:         "reference",
			Runbook:           "runbook",
		},
		{
			RuleID:          aws.String("ruleId"),
			RuleVersion:     aws.String("ruleVersion"),
			AlertID:         "alertId",
			Status:          "TRIAGED",
			Type:            "RULE",
			UpdateTime:      aws.Time(timeInTest),
			CreationTime:    aws.Time(timeInTest),
			Severity:        aws.String("INFO"),
			DedupString:     aws.String("dedupString"),
			EventsMatched:   aws.Int(100),
			RuleDisplayName: aws.String("ruleDisplayName"),
			// Since there is no dynamically generated title,
			// we return the display name
			Title:             aws.String("ruleDisplayName"),
			LogTypes:          []string{"AWS.CloudTrail"},
			ResourceTypes:     []string{"AWS.ResourceType"},
			ResourceID:        "resourceId",
			LastUpdatedBy:     "userId",
			LastUpdatedByTime: timeInTest,
			DeliveryResponses: []*models.DeliveryResponse{},
			Description:       "description",
			Reference:         "reference",
			Runbook:           "runbook",
		},
	}

	input := &models.ListAlertsInput{
		PageSize:          aws.Int(10),
		ExclusiveStartKey: aws.String("startKey"),
	}

	// Mock what is returned from DDB
	api.mockTable.On("ListAll", input).Return(alertItems, aws.String("lastKey"), nil)

	api.mockRuleCache.On("Get", "ruleId", "ruleVersion").Return(&rulemodels.Rule{}, nil).Once()

	result, err := api.ListAlerts(input)
	assert.NoError(t, err)
	assert.Equal(t, &models.ListAlertsOutput{
		Alerts:           expectedAlertSummary,
		LastEvaluatedKey: aws.String("lastKey"),
	}, result)

	api.AssertExpectations(t)
}
