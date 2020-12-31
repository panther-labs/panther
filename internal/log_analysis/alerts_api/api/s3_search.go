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
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
)

const (
	s3SelectConcurrency = 50 // not too big or you will get throttled!
)

type S3Search struct {
	maxResults  int
	concurrency int
	list        *s3.ListObjectsV2Input
	alert       *table.AlertItem
	client      s3iface.S3API
}

type S3SearchResult struct {
	events          []string
	lastS3ObjectKey string
	lastEventIndex  int
}

func newS3Search(client s3iface.S3API, list *s3.ListObjectsV2Input, alert *table.AlertItem, maxResults int) *S3Search {
	return &S3Search{
		alert:       alert,
		client:      client,
		list:        list,
		concurrency: s3SelectConcurrency,
		maxResults:  maxResults,
	}
}

// Do runs the search for the objects specified
// It will retrieve results by query each S3 object in parallel, using S3 Select
func (s *S3Search) Do(ctx context.Context) (*S3SearchResult, error) {
	var paginationErr error
	out := &S3SearchResult{}
	out.lastS3ObjectKey = aws.StringValue(s.list.StartAfter)
	err := s.client.ListObjectsV2PagesWithContext(ctx, s.list, func(output *s3.ListObjectsV2Output, lastPage bool) bool {
		results, err := s.queryPage(ctx, output.Contents)
		if err != nil {
			paginationErr = err
			return false
		}
		for _, result := range results {
			out.lastS3ObjectKey = result.objectKey
			for _, event := range result.events {
				out.events = append(out.events, event.payload)
				out.lastEventIndex = event.index
				if len(out.events) >= s.maxResults {
					return false
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	if paginationErr != nil {
		return nil, paginationErr
	}
	return out, nil
}

func (s *S3Search) queryPage(ctx context.Context, objects []*s3.Object) ([]*S3SelectResult, error) {
	queryChan := make(chan *S3Select, s.concurrency)
	resultChan := make(chan *S3SelectResult, s.concurrency)

	zap.L().Debug("starting to query page", zap.Int("objects", len(objects)))
	defer zap.L().Debug("finished querying page", zap.Int("objects", len(objects)))

	// singleton collector go routine, workers write data to here
	var results []*S3SelectResult
	collector, _ := errgroup.WithContext(ctx)
	collector.Go(func() error {
		for result := range resultChan {
			results = append(results, result)
		}
		return nil
	})

	// worker group doing concurrent queries writing to collector
	workerGroup, workerCtx := errgroup.WithContext(ctx)
	for i := 0; i < s.concurrency; i++ {
		workerGroup.Go(func() error {
			for query := range queryChan {
				if err := query.QueryAsync(workerCtx, resultChan); err != nil {
					return err
				}
			}
			return nil
		})
	}

	// drive requests thru the worker group
	var driverErr error
	for _, object := range objects {
		var objectTime time.Time
		objectTime, driverErr = timeFromJSONS3ObjectKey(*object.Key)
		if driverErr != nil {
			break
		}
		if objectTime.Before(getFirstEventTime(s.alert)) || objectTime.After(s.alert.UpdateTime) {
			// if the time in the S3 object key was before alert creation time or after last alert update time
			// skip the object
			continue
		}
		s3SelectQuery := &S3Select{
			bucket:     *s.list.Bucket,
			client:     s.client,
			objectKey:  *object.Key,
			alertID:    s.alert.AlertID,
			maxResults: s.maxResults,
		}
		queryChan <- s3SelectQuery
	}

	// this will signal workers to stop
	close(queryChan)

	// if the driver failed, close results channel to stop collector and return
	if driverErr != nil {
		close(resultChan)
		return nil, driverErr
	}

	// wait for workers to write everything into resultChan
	if err := workerGroup.Wait(); err != nil {
		close(resultChan)
		return nil, err
	}

	// this will signal collector to stop
	close(resultChan)

	// wait for collector to drain resultChan
	if err := collector.Wait(); err != nil {
		return nil, err
	}

	// results come in arbitrary order, sort
	sort.Slice(results, func(i, j int) bool {
		return results[i].objectKey < results[j].objectKey
	})

	return results, nil
}

// extracts time from the JSON S3 object key
// Key is expected to be in the format `/table/partitionkey=partitionvalue/.../time-uuid4.json.gz` otherwise the method will fail
func timeFromJSONS3ObjectKey(key string) (time.Time, error) {
	keyParts := strings.Split(key, "/")
	timeInString := strings.Split(keyParts[len(keyParts)-1], "-")[0]
	return time.ParseInLocation(destinations.S3ObjectTimestampLayout, timeInString, time.UTC)
}
