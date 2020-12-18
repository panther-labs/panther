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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	alertmodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/utils"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

const (
	s3SelectQueryBuffer = 1000 // how many listed events we allow in flight
	s3SelectConcurrency = 50   // not too big or you will get throttled!

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
		zap.L().Info("GetAlert paging",
			zap.Int("pageSize", *input.EventsPageSize),
			zap.Any("token", *token))
	}

	var events []string
	for _, logType := range alertItem.LogTypes {
		// Each alert can contain events from multiple log types.
		// Retrieve results from each log type.
		if logTypeToken, found := token.LogTypeToToken[logType]; found {
			if logTypeToken.EventIndex == -1 { // if -1 then already searched this logType completely
				continue
			}
		}

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

	// TODO: We should hit the rule cache ONLY for "old" alerts and only for alerts related to Rules or Rules errors
	alertRule, err := api.ruleCache.Get(alertItem.RuleID, alertItem.RuleVersion)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get rule with ID %s (version %s)",
			alertItem.RuleID, alertItem.RuleVersion)
	}

	alertSummary := utils.AlertItemToSummary(alertItem, alertRule)

	result = &models.Alert{
		AlertSummary:           *alertSummary,
		Events:                 aws.StringSlice(events),
		EventsLastEvaluatedKey: &encodedToken,
	}

	zap.L().Info("GetAlert",
		zap.Int("pageSize", *input.EventsPageSize),
		zap.Any("token", *token),
		zap.Any("events", events),
		zap.Int("nevents", len(events)))

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
		s3SelectQuery := &s3SelectQuery{
			objectKey:           token.S3ObjectKey,
			alertID:             alert.AlertID,
			exclusiveStartIndex: token.EventIndex,
			maxResults:          maxResults,
		}
		s3SelectResult := api.queryS3Object(s3SelectQuery)
		if s3SelectResult.err != nil {
			return nil, resultToken, s3SelectResult.err
		}
		// start iterating over the partitions here
		gluePartition, err := awsglue.PartitionFromS3Object(api.env.ProcessedDataBucket, token.S3ObjectKey)
		if err != nil {
			return nil, resultToken, errors.Wrapf(err, "cannot parse token s3 path")
		}
		nextTime = gluePartition.GetTime()
		// updating index in token with index of last event returned
		resultToken.S3ObjectKey = token.S3ObjectKey
		resultToken.EventIndex = s3SelectResult.lastEventIndex
		// done?
		if len(result)+len(s3SelectResult.events) >= maxResults {
			// clip, don't got over!
			events := s3SelectResult.events
			numOver := len(result) + len(events) - maxResults
			if numOver > 0 {
				events = events[0:numOver]
				resultToken.EventIndex = s3SelectResult.lastEventIndex - numOver
			}
			result = append(result, events...)
			return result, resultToken, nil
		} else {
			result = append(result, s3SelectResult.events...)
		}
	}

	// data is stored by hour, loop over the hours
	for ; !nextTime.After(alert.UpdateTime); nextTime = awsglue.GlueTableHourly.Next(nextTime) {
		database := pantherdb.RuleMatchDatabase
		if alert.Type == alertmodels.RuleErrorType {
			database = pantherdb.RuleErrorsDatabase
		}
		tableName := pantherdb.TableName(logType)
		partitionPrefix := awsglue.PartitionPrefix(database, tableName, awsglue.GlueTableHourly, nextTime)
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

		// list concurrently while searching for matches within this hour
		s3Search, err := api.newS3Search(listRequest, alert, maxResults)
		if err != nil {
			return nil, resultToken, err
		}
		// collect results for this hour
		s3Search.wait()

		for _, s3SelectResult := range s3Search.s3SelectResultsFound {
			if s3SelectResult.err != nil {
				return nil, resultToken, s3SelectResult.err
			}

			resultToken.EventIndex = s3SelectResult.lastEventIndex
			resultToken.S3ObjectKey = s3SelectResult.objectKey

			// done?
			if len(result)+len(s3SelectResult.events) >= maxResults {
				// clip, don't go over!
				events := s3SelectResult.events
				numOver := len(result) + len(events) - maxResults
				if numOver > 0 {
					events = events[0 : len(events)-numOver]
					resultToken.EventIndex = s3SelectResult.lastEventIndex - numOver
				}
				result = append(result, events...)

				return result, resultToken, nil
			} else {
				result = append(result, s3SelectResult.events...)
			}
		}
	}
	// if we a here we have finished the log type but there is more space in the page
	resultToken.EventIndex = -1 // mark as complete
	return result, resultToken, nil
}

type s3Search struct {
	api        *API
	maxResults int

	s3SelectListChan         chan struct{} // used to signal the listing that it can stop
	s3SelectQueryChan        chan *s3SelectQuery
	s3SelectResultChan       chan *s3SelectResult
	s3SelectQueryWaitGroup   sync.WaitGroup
	s3SelectTotalEventsFound uint32

	s3SelectCollectWaitGroup sync.WaitGroup
	s3SelectResultsFound     []*s3SelectResult
}

func (api *API) newS3Search(listRequest *s3.ListObjectsV2Input, alert *table.AlertItem, maxResults int) (search *s3Search, err error) {
	search = &s3Search{
		api:                api,
		maxResults:         maxResults,
		s3SelectListChan:   make(chan struct{}, s3SelectConcurrency), // one for each go routine so they can write and exit
		s3SelectQueryChan:  make(chan *s3SelectQuery, s3SelectQueryBuffer),
		s3SelectResultChan: make(chan *s3SelectResult, s3SelectQueryBuffer),
	}

	for i := 0; i < s3SelectConcurrency; i++ {
		search.s3SelectQueryWaitGroup.Add(1)
		go func() {
			for s3SelectQuery := range search.s3SelectQueryChan {
				s3SelectResult := api.queryS3Object(s3SelectQuery)
				search.s3SelectResultChan <- &s3SelectResult
				// protect tally with atomic
				atomic.AddUint32(&search.s3SelectTotalEventsFound, uint32(len(s3SelectResult.events)))
				if int(search.s3SelectTotalEventsFound) >= maxResults || s3SelectResult.err != nil {
					search.s3SelectListChan <- struct{}{} // signal listing to stop
					break
				}
			}
			search.s3SelectQueryWaitGroup.Done()
		}()
	}

	// here we collect from all the searching go routines using a single go routine
	search.s3SelectCollectWaitGroup.Add(1)
	go func() {
		for s3SelectResult := range search.s3SelectResultChan {
			search.s3SelectResultsFound = append(search.s3SelectResultsFound, s3SelectResult)
		}
		search.s3SelectCollectWaitGroup.Done()
	}()

	// list objects and send to the above go routines
	return search, search.listS3AlertObjects(listRequest, alert, maxResults)
}

func (search *s3Search) wait() {
	close(search.s3SelectQueryChan)
	search.s3SelectQueryWaitGroup.Wait()
	close(search.s3SelectResultChan)
	search.s3SelectCollectWaitGroup.Wait()

	// object keys are ordered but they can be returned in any order in the slice, so sort
	sort.Slice(search.s3SelectResultsFound, func(i, j int) bool {
		return search.s3SelectResultsFound[i].objectKey > search.s3SelectResultsFound[j].objectKey
	})
}

func (search *s3Search) listS3AlertObjects(listRequest *s3.ListObjectsV2Input, alert *table.AlertItem, maxResults int) (err error) {
	var paginationError error
	err = search.api.s3Client.ListObjectsV2Pages(listRequest, func(output *s3.ListObjectsV2Output, lastPage bool) bool {
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
			s3SelectQuery := &s3SelectQuery{
				objectKey:  *object.Key,
				alertID:    alert.AlertID,
				maxResults: maxResults,
			}
			search.s3SelectQueryChan <- s3SelectQuery

			// done?
			select {
			case <-search.s3SelectListChan:
				return false
			default: // make non-blocking
			}
		}
		// keep paginating
		return true
	})
	if err == nil && paginationError != nil {
		return paginationError
	}
	return err
}

// extracts time from the JSON S3 object key
// Key is expected to be in the format `/table/partitionkey=partitionvalue/.../time-uuid4.json.gz` otherwise the method will fail
func timeFromJSONS3ObjectKey(key string) (time.Time, error) {
	keyParts := strings.Split(key, "/")
	timeInString := strings.Split(keyParts[len(keyParts)-1], "-")[0]
	return time.ParseInLocation(destinations.S3ObjectTimestampLayout, timeInString, time.UTC)
}

type s3SelectQuery struct {
	objectKey           string
	alertID             string
	exclusiveStartIndex int
	maxResults          int
}

type s3SelectResult struct {
	objectKey      string
	events         []string
	lastEventIndex int
	err            error
}

// Queries a specific S3 object events associated to `alertID`.
// Returns :
// 1. The events that are associated to the given alertID that are present in that S3 object. It will return maximum `maxResults` events
// 2. The index of the last event returned. This will be used as a pagination token - future queries to the same S3 object can start listing
// after that.
func (api *API) queryS3Object(s3SelectQuery *s3SelectQuery) (s3SelectResult s3SelectResult) {
	s3SelectResult.objectKey = s3SelectQuery.objectKey

	// nolint:gosec
	// The alertID is an MD5 hash. AlertsAPI is performing the appropriate validation
	query := fmt.Sprintf("SELECT * FROM S3Object o WHERE o.p_alert_id='%s'", s3SelectQuery.alertID)

	zap.L().Debug("querying object using S3 Select",
		zap.String("S3ObjectKey", s3SelectQuery.objectKey),
		zap.String("query", query),
		zap.Int("index", s3SelectQuery.exclusiveStartIndex))
	input := &s3.SelectObjectContentInput{
		Bucket: &api.env.ProcessedDataBucket,
		Key:    &s3SelectQuery.objectKey,
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
		s3SelectResult.err = err
		return s3SelectResult
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
		s3SelectResult.err = streamError
		return s3SelectResult
	}

	currentIndex := 0
	var result []string
	for _, record := range strings.Split(payloadBuffer.String(), recordDelimiter) {
		if record == "" {
			continue
		}
		if len(result) >= s3SelectQuery.maxResults { // if we have received max results no need to get more events
			break
		}
		currentIndex++
		if currentIndex <= s3SelectQuery.exclusiveStartIndex { // we want to skip the results prior to exclusiveStartIndex
			continue
		}
		result = append(result, record)
	}
	s3SelectResult.events = result
	s3SelectResult.lastEventIndex = currentIndex
	return s3SelectResult
}

func getFirstEventTime(alert *table.AlertItem) time.Time {
	if alert.FirstEventMatchTime.IsZero() {
		// This check is for backward compatibility since
		// `FirstEventMatchTime` is a new field and many alerts might not have it
		return alert.CreationTime
	}
	return alert.FirstEventMatchTime
}
