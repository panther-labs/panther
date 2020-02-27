package api

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
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// GetAlert retrieves details for a given alert
func (API) GetAlert(input *models.GetAlertInput) (result *models.GetAlertOutput, err error) {
	operation := common.OpLogManager.Start("getAlert")
	defer func() {
		operation.Stop()
		operation.Log(err)
	}()

	alertItem, err := alertsDB.GetAlert(input.AlertID)
	if err != nil {
		return nil, err
	}

	var inputToken *paginationToken
	if input.EventsExclusiveStartKey != nil {
		inputToken, err = decodePaginationToken(*input.EventsExclusiveStartKey)
		if err != nil {
			return nil, err
		}
	}

	outputToken := &paginationToken{
		alreadyProcessed: make(map[string]int),
	}
	events := []string{}
	remainingItemsToRetrieve := aws.IntValue(input.EventsPageSize)
	for logType, eventsMatched := range alertItem.LogTypesEvents {
		startIndex := 0
		if inputToken != nil {
			if inputToken.alreadyProcessed[logType] == alertItem.LogTypesEvents[logType] {
				outputToken.alreadyProcessed[logType] = inputToken.alreadyProcessed[logType]
				continue
			}
			startIndex = inputToken.alreadyProcessed[logType]
		}

		eventsReturned, err := getEvents(logType, startIndex, alertItem.CreationTime, alertItem.UpdateTime, minInt(remainingItemsToRetrieve, eventsMatched))
		if err != nil {
			return nil, err
		}
		remainingItemsToRetrieve -= len(eventsReturned)
		events = append(events, eventsReturned...)
	}

	result = &models.Alert{
		AlertID:       &alertItem.AlertID,
		RuleID:        &alertItem.RuleID,
		CreationTime:  &alertItem.CreationTime,
		UpdateTime:    &alertItem.UpdateTime,
		EventsMatched: &alertItem.EventCount,
	}

	gatewayapi.ReplaceMapSliceNils(result)
	return result, nil
}

func minInt(value1, value2 int) int {
	if value1 < value2 {
		return value1
	}
	return value2
}

func getEvents(logType string, startIndex int, startTime, endTime time.Time, maxResults int) ([]string, error) {
	return nil, nil
}
