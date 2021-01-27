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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/utils"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

const (
	// The format of S3 object suffix that contains the
	ruleSuffixFormat = "rule_id=%s/"

	recordDelimiter = "\n"
)

// GetAlert retrieves details for a given alert
func (api *API) GetAlert(input *models.GetAlertInput) (*models.GetAlertOutput, error) {
	alertItem, err := api.alertsDB.GetAlert(input.AlertID)
	if err != nil {
		return nil, err
	}

	if alertItem == nil {
		return nil, nil
	}

	var token *EventPaginationToken
	if input.EventsExclusiveStartKey == nil {
		token = newPaginationToken()
	} else {
		token, err = decodePaginationToken(*input.EventsExclusiveStartKey)
		if err != nil {
			return nil, err
		}
	}

	zap.L().Debug("GetAlert request",
		zap.Int("pageSize", aws.IntValue(input.EventsPageSize)),
		zap.Any("token", token))

	var events []string
	for _, logType := range alertItem.LogTypes {
		// Each alert can contain events from multiple log types.
		// Retrieve results from each log type.

		// We only need to retrieve as many returns as to fit the EventsPageSize given by the user
		eventsToReturn := *input.EventsPageSize - len(events)
		eventsReturned, resultToken, getEventsErr := api.getEventsForLogType(logType, token.LogTypeToToken[logType],
			alertItem, eventsToReturn)
		if getEventsErr != nil {
			err = getEventsErr // set err so it is captured in oplog
			return nil, err
		}
		token.LogTypeToToken[logType] = resultToken
		events = append(events, eventsReturned...)
		if len(events) >= *input.EventsPageSize {
			// if we reached max result size, stop
			break
		}
	}

	encodedToken, err := token.encode()
	if err != nil {
		return nil, err
	}

	zap.L().Debug("GetAlert response",
		zap.Int("pageSize", *input.EventsPageSize),
		zap.Any("token", token),
		zap.Int("events", len(events)))

	// TODO: We should hit the rule cache ONLY for "old" alerts and only for alerts related to Rules or Rules errors
	alertRule, err := api.ruleCache.Get(alertItem.RuleID, alertItem.RuleVersion)
	if err != nil {
		zap.L().Warn("failed to get details for rule",
			zap.String("ruleId", alertItem.RuleID),
			zap.String("ruleVersion", alertItem.RuleVersion))
	}

	alertSummary := utils.AlertItemToSummary(alertItem, alertRule)

	return &models.Alert{
		AlertSummary:           *alertSummary,
		Events:                 events,
		EventsLastEvaluatedKey: &encodedToken,
	}, nil
}

// This method returns events from a specific log type that are associated to a given alert.
// It will only return up to `maxResults` events
func (api *API) getEventsForLogType(
	logType string,
	token *LogTypeToken,
	alert *table.AlertItem,
	maxResults int) ([]string, *LogTypeToken, error) {

	var outEvents []string
	var outToken LogTypeToken

	if token != nil {
		// If the token was not null
		// make sure to query the S3 Object included in it!!!
		// There would be more events in that object that we skipped in the previous pagination
		query := &S3Select{
			client:              api.s3Client,
			bucket:              api.env.ProcessedDataBucket,
			objectKey:           token.S3ObjectKey,
			alertID:             alert.AlertID,
			exclusiveStartIndex: token.EventIndex,
			maxResults:          maxResults,
		}
		s3SelectResult, err := query.Query(context.TODO())
		if err != nil {
			return nil, nil, err
		}

		outToken.S3ObjectKey = token.S3ObjectKey
		for _, event := range s3SelectResult.events {
			outEvents = append(outEvents, event.payload)
			outToken.EventIndex = event.index
		}

		// If the query returned sufficient results, just return
		if len(outEvents) >= maxResults {
			return outEvents, &outToken, nil
		}
	}

	var partitionTime time.Time
	if token != nil {
		// Now that we already got all the results from the  first S3 object start iterating over the rest of the partitions here
		gluePartition, err := awsglue.PartitionFromS3Object(api.env.ProcessedDataBucket, token.S3ObjectKey)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "cannot parse token s3 path")
		}
		// Set as starting partition time, the time of the S3 object included in the pagination token
		partitionTime = gluePartition.GetTime()
	} else {
		//  Set as starting partition time, the time the first event was matched. This information is available from the DDB data
		partitionTime = getFirstEventTime(alert)
	}

	// data is stored by hour, loop over the hours
	for ; !partitionTime.After(alert.UpdateTime); partitionTime = awsglue.GlueTableHourly.Next(partitionTime) {
		database := pantherdb.RuleMatchDatabase
		if alert.Type == deliverymodel.RuleErrorType {
			database = pantherdb.RuleErrorsDatabase
		}
		tableName := pantherdb.TableName(logType)
		partitionPrefix := awsglue.PartitionPrefix(database, tableName, awsglue.GlueTableHourly, partitionTime)
		partitionPrefix += fmt.Sprintf(ruleSuffixFormat, alert.RuleID) // JSON data has more specific paths based on ruleID

		listRequest := &s3.ListObjectsV2Input{
			Bucket: &api.env.ProcessedDataBucket,
			Prefix: &partitionPrefix,
		}

		// if we are paginating and in the same partition, set the cursor
		if token != nil {
			if strings.HasPrefix(token.S3ObjectKey, partitionPrefix) {
				listRequest.StartAfter = &token.S3ObjectKey
			}
		} else { // not starting from a pagination token
			// objects have a creation time as prefix we can use to speed listing,
			// for example: '20200914T021539Z-0e54cab2-80a6-4c27-b622-55ad4d355175.json.gz'
			listRequest.StartAfter = aws.String(partitionPrefix + partitionTime.Format("20060102T150405Z"))
		}

		// Search for up to remaining events
		s3Search := newS3Search(api.s3Client, listRequest, alert, maxResults-len(outEvents))
		searchResult, err := s3Search.Do(context.TODO())
		if err != nil {
			return nil, nil, err
		}
		outEvents = append(outEvents, searchResult.events...)
		outToken.EventIndex = searchResult.lastEventIndex
		outToken.S3ObjectKey = searchResult.lastS3ObjectKey
		if len(outEvents) >= maxResults {
			break
		}
	}
	return outEvents, &outToken, nil
}

func getFirstEventTime(alert *table.AlertItem) time.Time {
	if alert.FirstEventMatchTime.IsZero() {
		// This check is for backward compatibility since
		// `FirstEventMatchTime` is a new field and many alerts might not have it
		return alert.CreationTime
	}
	return alert.FirstEventMatchTime
}
