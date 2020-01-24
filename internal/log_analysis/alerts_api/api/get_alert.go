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
	"bytes"
	"encoding/hex"

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

	result = &models.Alert{
		AlertID:          alertItem.AlertID,
		RuleID:           alertItem.RuleID,
		CreationTime:     alertItem.CreationTime,
		LastEventMatched: alertItem.LastEventMatched,
		MatchedEventNum:  aws.Int(len(alertItem.EventHashes)),
	}

	var eventHashesToReturn [][]byte

	if input.EventsPageSize == nil { // if no eventsPageSize is defined, fallback to returning every event.
		eventHashesToReturn = alertItem.EventHashes
	} else {
		if input.EventsExclusiveStartKey == nil {
			// if no EventsExclusiveStartKey is defined, return the first events
			endIndex := len(alertItem.EventHashes)

			// If the full events are more than the page size
			// just return as many events as the page size
			// and set the lastEvaluatedKey
			if endIndex > *input.EventsPageSize {
				endIndex = *input.EventsPageSize
				lastHashToReturn := hex.EncodeToString(alertItem.EventHashes[endIndex-1])
				result.EventsLastEvaluatedKey = &lastHashToReturn
			}
			eventHashesToReturn = alertItem.EventHashes[:endIndex]
		} else {
			exclusiveStartKey, err := hex.DecodeString(*input.EventsExclusiveStartKey)
			if err != nil {
				return nil, err
			}
			for i, hash := range alertItem.EventHashes {
				if bytes.Equal(exclusiveStartKey, hash) {
					// We add 1 because the key is exclusive
					startIndex := i + 1
					endIndex := len(alertItem.EventHashes)

					// If the full events are more than the page size
					// just return as many events as the page size
					// and set the lastEvaluatedKey
					if endIndex > startIndex+*input.EventsPageSize {
						endIndex = startIndex + *input.EventsPageSize
						lastHashToReturn := hex.EncodeToString(alertItem.EventHashes[endIndex-1])
						result.EventsLastEvaluatedKey = &lastHashToReturn
					}
					eventHashesToReturn = alertItem.EventHashes[startIndex:endIndex]
					break
				}
			}
		}
	}

	for _, hash := range eventHashesToReturn {
		newEvent, err := alertsDB.GetEvent(hash)
		if err != nil {
			return nil, err
		}
		result.Events = append(result.Events, newEvent)
	}

	gatewayapi.ReplaceMapSliceNils(result)
	return result, nil
}
