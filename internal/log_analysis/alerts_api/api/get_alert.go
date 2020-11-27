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
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	alertmodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/core/pantherdb"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/utils"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	// The format of S3 object suffix that contains the
	ruleSuffixFormat = "rule_id=%s/"

	recordDelimiter = "\n"
)

// GetAlert retrieves details for a given alert
func (api *API) GetAlert(input *models.GetAlertInput) (result *models.GetAlertOutput, err error) {
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

	alertSummary := utils.AlertItemToSummary(alertItem)

	result = &models.Alert{
		AlertSummary:           *alertSummary,
		Events:                 aws.StringSlice(events),
		EventsLastEvaluatedKey: &encodedToken,
	}

	genericapi.ReplaceMapSliceNils(result)
	return result, nil
}

// This method returns events from a specific log type that are associated to a given alert.
// It will only return up to `maxResults` events
func (api *API) getEventsForLogType(
	logType string,
	token *LogTypeToken,
	alert *table.AlertItem,
	maxResults int) (result []string, resultToken *LogTypeToken, err error) {

	resultToken = &LogTypeToken{}

	nextTime := getFirstEventTime(alert)

	if token != nil {
		events, index, err := api.queryS3Object(token.S3ObjectKey, alert.AlertID, token.EventIndex, maxResults)
		if err != nil {
			return nil, resultToken, err
		}
		result = append(result, events...)
		// start iterating over the partitions here
		gluePartition, err := awsglue.GetPartitionFromS3(api.env.ProcessedDataBucket, token.S3ObjectKey)
		if err != nil {
			return nil, resultToken, errors.Wrapf(err, "cannot parse token s3 path")
		}
		nextTime = gluePartition.GetTime()
		// updating index in token with index of last event returned
		resultToken.S3ObjectKey = token.S3ObjectKey
		resultToken.EventIndex = index
		if len(result) >= maxResults {
			return result, resultToken, nil
		}
	}

	for ; !nextTime.After(alert.UpdateTime); nextTime = awsglue.GlueTableHourly.Next(nextTime) {
		if len(result) >= maxResults {
			// We don't need to return any results since we have already found the max requested
			break
		}

		database := pantherdb.RuleMatchDatabase
		if alert.Type == alertmodels.RuleErrorType {
			database = pantherdb.RuleErrorsDatabase
		}
		partitionPrefix := awsglue.GetPartitionPrefix(database, logType, awsglue.GlueTableHourly, nextTime)
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
			listRequest.StartAfter = aws.String(partitionPrefix + nextTime.Format("20060102T150405Z"))
		}

		var paginationError error

		err := api.s3Client.ListObjectsV2Pages(listRequest, func(output *s3.ListObjectsV2Output, lastPage bool) bool {
			for _, object := range output.Contents {
				objectTime, err := timeFromJSONS3ObjectKey(*object.Key)
				if err != nil {
					zap.L().Error("failed to parse object time from S3 object key",
						zap.String("key", *object.Key))
					paginationError = err
					return false
				}
				if objectTime.Before(getFirstEventTime(alert)) || objectTime.After(alert.UpdateTime) {
					// if the time in the S3 object key was before alert creation time or after last alert update time
					// skip the object
					continue
				}
				events, EventIndex, err := api.queryS3Object(*object.Key, alert.AlertID, 0, maxResults-len(result))
				if err != nil {
					paginationError = err
					return false
				}
				result = append(result, events...)
				resultToken.EventIndex = EventIndex
				resultToken.S3ObjectKey = *object.Key
				if len(result) >= maxResults {
					// if we have already received all the results we wanted
					// no need to keep paginating
					return false
				}
			}
			// keep paginating
			return true
		})

		if err != nil {
			return nil, resultToken, err
		}

		if paginationError != nil {
			return nil, resultToken, paginationError
		}
	}
	return result, resultToken, nil
}

// extracts time from the JSON S3 object key
// Key is expected to be in the format `/table/partitionkey=partitionvalue/.../time-uuid4.json.gz` otherwise the method will fail
func timeFromJSONS3ObjectKey(key string) (time.Time, error) {
	keyParts := strings.Split(key, "/")
	timeInString := strings.Split(keyParts[len(keyParts)-1], "-")[0]
	return time.ParseInLocation(destinations.S3ObjectTimestampLayout, timeInString, time.UTC)
}

// Queries a specific S3 object events associated to `alertID`.
// Returns :
// 1. The events that are associated to the given alertID that are present in that S3 oject. It will return maximum `maxResults` events
// 2. The index of the last event returned. This will be used as a pagination token - future queries to the same S3 object can start listing
// after that.
func (api *API) queryS3Object(key, alertID string, exclusiveStartIndex, maxResults int) ([]string, int, error) {
	// nolint:gosec
	// The alertID is an MD5 hash. AlertsAPI is performing the appropriate validation
	query := fmt.Sprintf("SELECT * FROM S3Object o WHERE o.p_alert_id='%s'", alertID)

	zap.L().Debug("querying object using S3 Select",
		zap.String("S3ObjectKey", key),
		zap.String("query", query),
		zap.Int("index", exclusiveStartIndex))
	input := &s3.SelectObjectContentInput{
		Bucket: &api.env.ProcessedDataBucket,
		Key:    &key,
		InputSerialization: &s3.InputSerialization{
			CompressionType: aws.String(s3.CompressionTypeGzip),
			JSON:            &s3.JSONInput{Type: aws.String(s3.JSONTypeLines)},
		},
		OutputSerialization: &s3.OutputSerialization{
			JSON: &s3.JSONOutput{RecordDelimiter: aws.String(recordDelimiter)},
		},
		ExpressionType: aws.String(s3.ExpressionTypeSql),
		Expression:     &query,
	}

	output, err := api.s3Client.SelectObjectContent(input)
	if err != nil {
		return nil, 0, err
	}

	// NOTE: Payloads are NOT broken on record boundaries! It is possible for rows to span ResultsEvent's so we need a buffer
	var payloadBuffer bytes.Buffer
	for genericEvent := range output.EventStream.Reader.Events() {
		switch e := genericEvent.(type) {
		case *s3.RecordsEvent:
			payloadBuffer.Write(e.Payload)
		case *s3.StatsEvent:
			continue
		}
	}
	streamError := output.EventStream.Reader.Err()
	if streamError != nil {
		return nil, 0, streamError
	}

	currentIndex := 0
	var result []string
	for _, record := range strings.Split(payloadBuffer.String(), recordDelimiter) {
		if record == "" {
			continue
		}
		if len(result) >= maxResults { // if we have received max results no need to get more events
			break
		}
		currentIndex++
		if currentIndex <= exclusiveStartIndex { // we want to skip the results prior to exclusiveStartIndex
			continue
		}
		result = append(result, record)
	}
	return result, currentIndex, nil
}

func getFirstEventTime(alert *table.AlertItem) time.Time {
	if alert.FirstEventMatchTime.IsZero() {
		// This check is for backward compatibility since
		// `FirstEventMatchTime` is a new field and many alerts might not have it
		return alert.CreationTime
	}
	return alert.FirstEventMatchTime
}
