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
	"sort"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// ListAlerts retrieves alert and event details.
func (API) ListAlerts(input *models.ListAlertsInput) (result *models.ListAlertsOutput, err error) {
	operation := common.OpLogManager.Start("listAlerts")
	defer func() {
		operation.Stop()
		operation.Log(err)
	}()

	result = &models.ListAlertsOutput{}
	var alertItems []*table.AlertItem
	if input.RuleID != nil { // list per specific ruleId
		alertItems, result.LastEvaluatedKey, err = alertsDB.ListByRule(*input.RuleID, input.ExclusiveStartKey, input.PageSize, input.Severity)
	} else { // list all alerts time desc order
		alertItems, result.LastEvaluatedKey, err = alertsDB.ListAll(input.ExclusiveStartKey, input.PageSize, input.Severity)
	}
	if err != nil {
		return nil, err
	}

	// TODO - the table already has a RANGE key for creationTime.
	//    Sorting by time could happen in the table query directly, instead of here
	switch aws.StringValue(input.SortBy) {
	case "title":
		sort.Slice(alertItems, func(i, j int) bool {
			return aws.StringValue(result.Alerts[i].Title) < aws.StringValue(result.Alerts[j].Title)
		})
	}

	// TODO - The returned pagination key is currently not valid when sorting.
	//    It is currently returned by Dynamo as the last key that was scanned.
	//    But Dynamo can't sort (except by time), so we need to construct the pagination key manually

	result.Alerts = alertItemsToAlertSummary(alertItems)

	gatewayapi.ReplaceMapSliceNils(result)
	return result, nil
}

// alertItemsToAlertSummary converts a DDB Alert Item to an Alert Summary that will be returned by the API
func alertItemsToAlertSummary(items []*table.AlertItem) []*models.AlertSummary {
	result := make([]*models.AlertSummary, len(items))

	for i, item := range items {
		result[i] = &models.AlertSummary{
			AlertID:         &item.AlertID,
			RuleID:          &item.RuleID,
			DedupString:     &item.DedupString,
			CreationTime:    &item.CreationTime,
			Severity:        &item.Severity,
			UpdateTime:      &item.UpdateTime,
			EventsMatched:   &item.EventCount,
			RuleDisplayName: item.RuleDisplayName,
			Title:           getAlertTitle(item),
			RuleVersion:     &item.RuleVersion,
		}
	}

	return result
}
