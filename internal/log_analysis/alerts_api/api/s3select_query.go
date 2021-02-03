package api

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"go.uber.org/zap"
)

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

type S3Select struct {
	client              s3iface.S3API
	bucket              string
	objectKey           string
	alertID             string
	exclusiveStartIndex int
	maxResults          int
}

type S3SelectResult struct {
	objectKey string
	events    []Event
}

type Event struct {
	index   int
	payload string
}

// Queries a specific S3 object events associated to `alertID`.
// Returns :
// 1. The events that are associated to the given alertID that are present in that S3 object. It will return maximum `maxResults` events
// 2. The index of the last event returned. This will be used as a pagination token - future queries to the same S3 object can start listing
// after that.
func (s *S3Select) Query(ctx context.Context) (*S3SelectResult, error) {
	out := &S3SelectResult{
		objectKey: s.objectKey,
	}

	// account for those we skip in loop below because there is no OFFSET support in S3 select
	maxResults := s.maxResults + s.exclusiveStartIndex

	// nolint:gosec
	// The alertID is an MD5 hash. AlertsAPI is performing the appropriate validation
	query := fmt.Sprintf("SELECT * FROM S3Object o WHERE o.p_alert_id='%s' LIMIT %d", s.alertID, maxResults)

	zap.L().Debug("querying object using S3 Select",
		zap.String("S3ObjectKey", s.objectKey),
		zap.String("query", query),
		zap.Int("index", s.exclusiveStartIndex))
	input := &s3.SelectObjectContentInput{
		Bucket: &s.bucket,
		Key:    &s.objectKey,
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

	output, err := s.client.SelectObjectContentWithContext(ctx, input)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	currentIndex := 0
	var result []Event
	for _, record := range strings.Split(payloadBuffer.String(), recordDelimiter) {
		if record == "" {
			continue
		}
		currentIndex++
		if currentIndex <= s.exclusiveStartIndex { // we want to skip the results prior to exclusiveStartIndex
			continue
		}
		result = append(result, Event{index: currentIndex, payload: record})
	}
	out.events = result
	return out, nil
}

// Same  as above, but writes the results in a channel
func (s *S3Select) QueryAsync(ctx context.Context, outChan chan<- *S3SelectResult) error {
	result, err := s.Query(ctx)
	if err != nil {
		return err
	}
	outChan <- result
	return nil
}
