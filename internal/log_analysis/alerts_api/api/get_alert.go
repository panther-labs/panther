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
	var token *paginationToken
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
		// retrieve events from each log type. Retrieve maximum the number of events remaining
		eventsReturned, err := getEventsForLogType(logType, token, alertItem, *input.EventsPageSize-len(events))
		if err != nil {
			return nil, err
		}
		events = append(events, eventsReturned...)
		if len(events) == *input.EventsPageSize {
			// if we reached max result size, stop
			break
		}
	}

	zap.L().Info("printing content2", zap.Any("token", token))

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

func getEventsForLogType(logType string, token *paginationToken, alert *models.AlertItem, maxResults int) (result []string, err error) {
	logTypeToken := token.logTypeToToken[logType]

	if logTypeToken != nil {
		events, index, err := queryS3Object(*logTypeToken.s3ObjectKey, alert.AlertID, *logTypeToken.eventIndex, maxResults)
		if err != nil {
			return nil, err
		}
		result = append(result, events...)
		// updating token with latest index
		logTypeToken.eventIndex = aws.Int(index)
		if len(result) == maxResults {
			return result, nil
		}
	} else {
		logTypeToken = &continuationToken{}
		token.logTypeToToken[logType] = logTypeToken
	}

	var partitionLocations []string
	for nextTime := alert.CreationTime; !nextTime.After(alert.UpdateTime); nextTime = awsglue.GlueTableHourly.Next(nextTime) {
		partitionLocation := awsglue.GeneratePartitionPrefix(logprocessormodels.RuleData, logType, awsglue.GlueTableHourly, nextTime)
		partitionLocations = append(partitionLocations, partitionLocation)
	}

	for _, partition := range partitionLocations {
		if len(result) == maxResults {
			// We don't need to return any results since we have already found the max requested
			break
		}
		prefix := partition + fmt.Sprintf(ruleSuffixFormat, alert.RuleID)

		listRequest := &s3.ListObjectsV2Input{
			Bucket:     aws.String(env.ProcessedDataBucket),
			Prefix:     aws.String(prefix),
			StartAfter: logTypeToken.s3ObjectKey,
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
					continue
				}
				events, eventIndex, err := queryS3Object(*object.Key, alert.AlertID, 0, maxResults-len(result))
				if err != nil {
					paginationError = err
					return false
				}
				result = append(result, events...)
				logTypeToken.eventIndex = aws.Int(eventIndex)
				logTypeToken.s3ObjectKey = object.Key
				zap.L().Info("printing content3", zap.Any("token", logTypeToken))
				zap.L().Info("printing content4", zap.Any("token", token))
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
			return nil, err
		}

		if paginationError != nil {
			return nil, paginationError
		}
	}
	zap.L().Info("printing content", zap.Any("token", token))
	return result, nil
}

// extracts the
func timeFromS3ObjectKey(key string) (time.Time, error) {
	// Key is in the format: /table/partitionkey=partitionvalue/.../time-uuid4.json.gz
	keyParts := strings.Split(key, "/")
	timeInString := strings.Split(keyParts[len(keyParts)-1], "-")[0]
	return time.ParseInLocation(destinations.S3ObjectTimestampFormat, timeInString, time.UTC)
}

func queryS3Object(key, alertID string, exclusiveStartIndex, maxResults int) ([]string, int, error) {
	// nolint:gosec
	query := fmt.Sprintf("SELECT * FROM S3Object o WHERE o.p_alert_id='%s'", alertID)

	zap.L().Debug("querying object using S3 Select",
		zap.String("s3ObjectKey", key),
		zap.String("query", query))
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
	processedResults := 0
	for genericEvent := range output.EventStream.Reader.Events() {
		switch e := genericEvent.(type) { // to specific event
		case *s3.RecordsEvent:
			if processedResults == maxResults { // if we have received max results no need to get more events
				// We still need to iterate through the contents of the EventStream
				// to avoid memory leaks
				continue
			}
			processedResults++
			if processedResults < exclusiveStartIndex { // we want to skip the results prior to exclusiveStartIndex
				continue
			}
			result = append(result, string(e.Payload))
		case *s3.StatsEvent:
			continue
		}
	}
	streamError := output.EventStream.Reader.Err()
	if streamError != nil {
		return nil, 0, streamError
	}
	return result, processedResults, nil
}
