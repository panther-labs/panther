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
	events := []string{}
	for _, logType := range alertItem.LogTypes {
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

func minInt(value1, value2 int) int {
	if value1 < value2 {
		return value1
	}
	return value2
}

func getEventsForLogType(logType string, token *paginationToken, alert *models.AlertItem, maxResults int) (resultEvents []string, err error) {

	if token.logTypeToLastEvent[logType] != nil {
		queryS3Object(token.logTypeToLastEvent[logType].key, alert.AlertID, )
	}

	queryS3Object()


	partitionLocations := []string{}
	for nextTime := alert.CreationTime; !nextTime.After(alert.UpdateTime); nextTime = awsglue.GlueTableHourly.Next(nextTime) {
		partitionLocation := awsglue.GeneratePartitionPrefix(logprocessormodels.RuleData, logType, awsglue.GlueTableHourly, nextTime)
		partitionLocations = append(partitionLocations, partitionLocation)
	}

	startTimeString := alert.CreationTime.Format(destinations.S3ObjectTimestampFormat)
	endTimeString := alert.UpdateTime.Format(destinations.S3ObjectTimestampFormat)

	processedEvents := 0
	for _, partition := range partitionLocations {
		if processedEvents == maxResults {
			// We don't need to return any results since we have already found the max requested
			break
		}
		prefix := partition + fmt.Sprintf(ruleSuffixFormat, alert.RuleID)



		if token.logTypeToLastEvent[logType] != nil {
			listRequest.StartAfter = aws.String(token.logTypeToLastEvent[logType].nextToLastKey)
		}

		listRequest := &s3.ListObjectsV2Input{
			Bucket: aws.String(env.ProcessedDataBucket),
			Prefix: aws.String(prefix),
		}
		err := s3Client.ListObjectsV2Pages(listRequest, func(output *s3.ListObjectsV2Output, b bool) bool {
			for i, object := range output.Contents {
				zap.L().Info("found data", zap.String("key", *object.Key))
				if *object.Key < startTimeString || *object.Key > endTimeString {
					continue
				}
				startIndex := 0
				if lastObjectProcessed != nil && *object.Key == lastObjectProcessed.key {
					startIndex = lastObjectProcessed.lastEvent
				}
				events, eventIndex, err := queryS3Object(*object.Key, alert.AlertID, startIndex, maxResults-processedEvents)
				if err != nil {
					return false
				}
				processedEvents += len(events)
				resultEvents = append(resultEvents, events...)
				lastObjectProcessedInfo.lastEvent = eventIndex
				if processedEvents == maxResults {
					// if we have already received all the results we wanted
					// no need to keep paginating
					return false
				}
			}
			// keep paginating
			return true
		})

		if err != nil {
			return nil, lastObjectProcessedInfo, err
		}
	}
	return resultEvents, lastObjectProcessedInfo, nil
}

func queryS3Object(key, alertID string, exclusiveStartIndex, maxResults int) ([]string, int, error) {
	query := fmt.Sprintf("select * from S3Object o WHERE o.p_alert_id='%s'", alertID)

	zap.L().Debug("querying object using S3 Select",
		zap.String("key", key),
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

	result := []string{}
	processedResults := 0
	for genericEvent := range output.EventStream.Reader.Events() {
		switch e := genericEvent.(type) { // to specific event
		case *s3.RecordsEvent:
			if processedResults == maxResults || // if we have received max results no need to get more events
				processedResults <= exclusiveStartIndex { // we want to skip the results prior to exclusiveStartIndex
				continue
			}
			processedResults++
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
