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
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	logprocessormodels "github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// The format of S3 object suffix that contains the
const ruleSuffixFormat = "rule_id=%s/"

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
	var token *EventPaginationToken
	if input.EventsExclusiveStartKey != nil {
		token, err = decodePaginationToken(*input.EventsExclusiveStartKey)
		if err != nil {
			return nil, err
		}
	} else {
		token = newPaginationToken()
	}
	var events []string
	for _, logType := range alertItem.LogTypes {
		// Each alert can contain events from multiple log types.
		// Retrieve results from each log type. We only need to retrieve maximum `input.EventsPageSize`
		eventsReturned, resultToken, err := getEventsForLogType(logType, token.LogTypeToToken[logType], alertItem, *input.EventsPageSize-len(events))
		zap.L().Info("got result token", zap.Any("resultToken", resultToken))
		zap.L().Info("got result token", zap.Any("key", resultToken.S3ObjectKey))
		zap.L().Info("got result token", zap.Any("index", resultToken.EventIndex))
		if err != nil {
			return nil, err
		}
		token.LogTypeToToken[logType] = resultToken
		events = append(events, eventsReturned...)
		if len(events) == *input.EventsPageSize {
			// if we reached max result size, stop
			break
		}
	}

	zap.L().Info("token will be", zap.Any("token", token))
	for key, value := range token.LogTypeToToken {
		zap.L().Info("Token to be returned",
			zap.String("logType", key),
			zap.String("S3ObjectKey", value.S3ObjectKey),
			zap.Int("EventIndex", value.EventIndex))
	}
	encodedToken, err := token.encode()
	if err != nil {
		return nil, err
	}
	result = &models.Alert{
		AlertID:                &alertItem.AlertID,
		RuleID:                 &alertItem.RuleID,
		CreationTime:           &alertItem.CreationTime,
		UpdateTime:             &alertItem.UpdateTime,
		EventsMatched:          &alertItem.EventCount,
		Events:                 aws.StringSlice(events),
		EventsLastEvaluatedKey: aws.String(encodedToken),
	}

	gatewayapi.ReplaceMapSliceNils(result)
	return result, nil
}

// This method returns events from a specific log type that are associated to a given alert.
// It will only return up to `maxResults` events
func getEventsForLogType(
	logType string, token *LogTypeToken, alert *models.AlertItem, maxResults int) (result []string, resultToken *LogTypeToken, err error) {
	resultToken = &LogTypeToken{}

	if token != nil {
		events, index, err := queryS3Object(token.S3ObjectKey, alert.AlertID, token.EventIndex, maxResults)
		if err != nil {
			return nil, resultToken, err
		}
		result = append(result, events...)
		// updating index in token with index of last event returned
		resultToken.S3ObjectKey = token.S3ObjectKey
		resultToken.EventIndex = index
		if len(result) == maxResults {
			return result, resultToken, nil
		}
	}

	var partitionLocations []string
	for nextTime := alert.CreationTime; !nextTime.After(alert.UpdateTime); nextTime = awsglue.GlueTableHourly.Next(nextTime) {
		partitionLocation := awsglue.GetPartitionPrefix(logprocessormodels.RuleData, logType, awsglue.GlueTableHourly, nextTime)
		partitionLocations = append(partitionLocations, partitionLocation)
	}

	for _, partition := range partitionLocations {
		if len(result) == maxResults {
			// We don't need to return any results since we have already found the max requested
			break
		}
		prefix := partition + fmt.Sprintf(ruleSuffixFormat, alert.RuleID)

		listRequest := &s3.ListObjectsV2Input{
			Bucket: aws.String(env.ProcessedDataBucket),
			Prefix: aws.String(prefix),
		}

		if token != nil {
			listRequest.StartAfter = aws.String(token.S3ObjectKey)
		}

		var paginationError error

		err := s3Client.ListObjectsV2Pages(listRequest, func(output *s3.ListObjectsV2Output, b bool) bool {
			for _, object := range output.Contents {
				objectTime, err := timeFromS3ObjectKey(*object.Key)
				if err != nil {
					zap.L().Error("failed to parse object time from S3 object key",
						zap.String("key", *object.Key))
					paginationError = err
					return false
				}
				if objectTime.Before(alert.CreationTime) || objectTime.After(alert.UpdateTime) {
					// if the time in the S3 object key was before alert creation time or after last alert update time
					// skip the object
					continue
				}
				events, EventIndex, err := queryS3Object(*object.Key, alert.AlertID, 0, maxResults-len(result))
				if err != nil {
					paginationError = err
					return false
				}
				result = append(result, events...)
				zap.L().Info("tokenbefore", zap.Any("resultToken", resultToken))
				resultToken.EventIndex = EventIndex
				resultToken.S3ObjectKey = *object.Key
				zap.L().Info("tokenafter", zap.Any("resultToken", resultToken))
				zap.L().Info("tokenafter", zap.Any("key", resultToken.S3ObjectKey))
				zap.L().Info("tokenafter", zap.Any("index", resultToken.EventIndex))
				if len(result) == maxResults {
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

// extracts time from the S3 object key
// Key is expected to be in the format `/table/partitionkey=partitionvalue/.../time-uuid4.json.gz` otherwise the method will fail
func timeFromS3ObjectKey(key string) (time.Time, error) {
	keyParts := strings.Split(key, "/")
	timeInString := strings.Split(keyParts[len(keyParts)-1], "-")[0]
	return time.ParseInLocation(destinations.S3ObjectTimestampFormat, timeInString, time.UTC)
}

// Queries a specific S3 object events associated to `alertID`.
// Returns :
// 1. The events that are associated to the given alertID that are present in that S3 oject. It will return maximum `maxResults` events
// 2. The index of the last event returned. This will be used as a pagination token - future queries to the same S3 object can start listing
// after that.
func queryS3Object(key, alertID string, exclusiveStartIndex, maxResults int) ([]string, int, error) {
	// nolint:gosec
	query := fmt.Sprintf("SELECT * FROM S3Object o WHERE o.p_alert_id='%s'", alertID)

	zap.L().Debug("querying object using S3 Select",
		zap.String("S3ObjectKey", key),
		zap.String("query", query),
		zap.Int("index", exclusiveStartIndex))
	input := &s3.SelectObjectContentInput{
		Bucket: aws.String(env.ProcessedDataBucket),
		Key:    aws.String(key),
		InputSerialization: &s3.InputSerialization{
			CompressionType: aws.String(s3.CompressionTypeGzip),
			JSON:            &s3.JSONInput{Type: aws.String(s3.JSONTypeLines)},
		},
		OutputSerialization: &s3.OutputSerialization{
			JSON: &s3.JSONOutput{},
		},
		ExpressionType: aws.String(s3.ExpressionTypeSql),
		Expression:     aws.String(query),
	}

	output, err := s3Client.SelectObjectContent(input)
	if err != nil {
		return nil, 0, err
	}

	var result []string
	currentIndex := 0
	for genericEvent := range output.EventStream.Reader.Events() {
		switch e := genericEvent.(type) { // to specific event
		case *s3.RecordsEvent:
			records := strings.Split(string(e.Payload), "\n")
			for _, record := range records {
				if len(result) == maxResults { // if we have received max results no need to get more events
					// We still need to iterate through the contents of the EventStream
					// to avoid memory leaks
					continue
				}
				currentIndex++
				if currentIndex <= exclusiveStartIndex { // we want to skip the results prior to exclusiveStartIndex
					continue
				}
				result = append(result, record)
			}
		case *s3.StatsEvent:
			continue
		}
	}
	streamError := output.EventStream.Reader.Err()
	if streamError != nil {
		return nil, 0, streamError
	}
	return result, currentIndex, nil
}
