package s3queue

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
	"fmt"
	"log"
	"math"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const (
	pageSize             = 1000
	fakeTopicArnTemplate = "arn:aws:sns:us-east-1:%s:panther-fake-s3queue-topic" // account is added for sqs messages
	progressNotify       = 5000                                                  // log a line every this many to show progress
)

type Stats struct {
	NumFiles uint64
	NumBytes uint64
}

func S3Queue(sess *session.Session, account, s3path, s3region, queueName string,
	concurrency int, limit uint64, stats *Stats) (err error) {

	return s3Queue(s3.New(sess.Copy(&aws.Config{Region: &s3region})), sqs.New(sess),
		account, s3path, queueName, concurrency, limit, stats)
}

func s3Queue(s3Client s3iface.S3API, sqsClient sqsiface.SQSAPI, account, s3path, queueName string,
	concurrency int, limit uint64, stats *Stats) (failed error) {

	queueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &queueName,
	})
	if err != nil {
		return errors.Wrapf(err, "could not get queue url for %s", queueName)
	}

	// the account id is taken from this arn to assume role for reading in the log processor
	topicARN := fmt.Sprintf(fakeTopicArnTemplate, account)

	errChan := make(chan error)
	notifyChan := make(chan *events.S3Event, 1000)

	var queueWg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		queueWg.Add(1)
		go func() {
			queueNotifications(sqsClient, topicARN, queueURL.QueueUrl, notifyChan, errChan)
			queueWg.Done()
		}()
	}

	queueWg.Add(1)
	go func() {
		listPath(s3Client, s3path, limit, notifyChan, errChan, stats)
		queueWg.Done()
	}()

	var errorWg sync.WaitGroup
	errorWg.Add(1)
	go func() {
		for err := range errChan { // return last error
			failed = err
		}
		errorWg.Done()
	}()

	queueWg.Wait()
	close(errChan)
	errorWg.Wait()

	return failed
}

// Given an s3path (e.g., s3://mybucket/myprefix) list files and send to notifyChan
func listPath(s3Client s3iface.S3API, s3path string, limit uint64,
	notifyChan chan *events.S3Event, errChan chan error, stats *Stats) {

	if limit == 0 {
		limit = math.MaxUint64
	}

	defer func() {
		close(notifyChan) // signal to reader that we are done
	}()

	parsedPath, err := url.Parse(s3path)
	if err != nil {
		errChan <- errors.Errorf("bad s3 url: %s,", err)
		return
	}

	if parsedPath.Scheme != "s3" {
		errChan <- errors.Errorf("not s3 protocol (expecting s3://): %s,", s3path)
		return
	}

	bucket := parsedPath.Host
	if bucket == "" {
		errChan <- errors.Errorf("missing bucket: %s,", s3path)
		return
	}
	var prefix string
	if len(parsedPath.Path) > 0 {
		prefix = parsedPath.Path[1:] // remove leading '/'
	}

	// list files w/pagination
	inputParams := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int64(pageSize),
	}
	err = s3Client.ListObjectsV2Pages(inputParams, func(page *s3.ListObjectsV2Output, morePages bool) bool {
		for _, value := range page.Contents {
			if *value.Size > 0 { // we only care about objects with size
				stats.NumFiles++
				if stats.NumFiles%progressNotify == 0 {
					log.Printf("listed %d files ...", stats.NumFiles)
				}
				stats.NumBytes += (uint64)(*value.Size)
				notifyChan <- &events.S3Event{
					Records: []events.S3EventRecord{
						{
							S3: events.S3Entity{
								Bucket: events.S3Bucket{
									Name: bucket,
								},
								Object: events.S3Object{
									Key:  *value.Key,
									Size: *value.Size,
								},
							},
						},
					},
				}
				if stats.NumFiles >= limit {
					break
				}
			}
		}
		return stats.NumFiles < limit // "To stop iterating, return false from the fn function."
	})
	if err != nil {
		errChan <- err
	}
}

// post message per file as-if it was an S3 notification
func queueNotifications(sqsClient sqsiface.SQSAPI, topicARN string, queueURL *string,
	notifyChan chan *events.S3Event, errChan chan error) {

	sendMessageBatchInput := &sqs.SendMessageBatchInput{
		QueueUrl: queueURL,
	}

	// we have 1 file per notification to limit blast radius in case of failure.
	const (
		batchTimeout = time.Minute
		batchSize    = 10
	)
	var failed bool
	for s3Notification := range notifyChan {
		if failed { // drain channel
			continue
		}

		zap.L().Debug("sending file to SQS",
			zap.String("bucket", s3Notification.Records[0].S3.Bucket.Name),
			zap.String("key", s3Notification.Records[0].S3.Object.Key))

		ctnJSON, err := jsoniter.MarshalToString(s3Notification)
		if err != nil {
			errChan <- errors.Wrapf(err, "failed to marshal %#v", s3Notification)
			failed = true
			continue
		}

		// make it look like an SNS notification
		snsNotification := events.SNSEntity{
			Type:     "Notification",
			TopicArn: topicARN, // this is needed by the log processor to get account associated with the S3 object
			Message:  ctnJSON,
		}
		message, err := jsoniter.MarshalToString(snsNotification)
		if err != nil {
			errChan <- errors.Wrapf(err, "failed to marshal %#v", snsNotification)
			failed = true
			continue
		}

		sendMessageBatchInput.Entries = append(sendMessageBatchInput.Entries, &sqs.SendMessageBatchRequestEntry{
			Id:          aws.String(strconv.Itoa(len(sendMessageBatchInput.Entries))),
			MessageBody: &message,
		})
		if len(sendMessageBatchInput.Entries)%batchSize == 0 {
			_, err = sqsbatch.SendMessageBatch(sqsClient, batchTimeout, sendMessageBatchInput)
			if err != nil {
				errChan <- errors.Wrapf(err, "failed to send %#v", sendMessageBatchInput)
				failed = true
				continue
			}
			sendMessageBatchInput.Entries = make([]*sqs.SendMessageBatchRequestEntry, 0, batchSize) // reset
		}
	}

	// send remaining
	if !failed && len(sendMessageBatchInput.Entries) > 0 {
		_, err := sqsbatch.SendMessageBatch(sqsClient, batchTimeout, sendMessageBatchInput)
		if err != nil {
			errChan <- errors.Wrapf(err, "failed to send %#v", sendMessageBatchInput)
		}
	}
}
