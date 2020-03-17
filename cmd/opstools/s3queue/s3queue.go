package s3queue

import (
	"fmt"
	"math"
	"net/url"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

const (
	concurrency          = 10
	pageSize             = 1000
	fakeTopicArnTemplate = "arn:aws:sns:us-east-1:%s:panther-fake-s3queue-topic" // account is added for sqs messages
)

type Stats struct {
	NumFiles uint64
	NumBytes uint64
}

type cloudTrailNotification struct {
	S3Bucket    *string   `json:"s3Bucket"`
	S3ObjectKey []*string `json:"s3ObjectKey"`
}

func S3Queue(sess *session.Session, account, s3path, queueName string, limit uint64, stats *Stats) (err error) {
	return s3Queue(s3.New(sess), sqs.New(sess), account, s3path, queueName, limit, stats)
}

func s3Queue(s3Client s3iface.S3API, sqsClient sqsiface.SQSAPI, account, s3path, queueName string,
	limit uint64, stats *Stats) (failed error) {

	queueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &queueName,
	})
	if err != nil {
		return errors.Wrapf(err, "could not get queue url for %s", queueName)
	}

	// the account id is taken from this  arn to assume role for reading in the log processor
	topicARN := fmt.Sprintf(fakeTopicArnTemplate, account)

	errChan := make(chan error)
	notifyChan := make(chan *cloudTrailNotification, 1000)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			queueNotifications(sqsClient, topicARN, queueURL.QueueUrl, notifyChan, errChan)
			wg.Done()
		}()
	}

	wg.Add(1)
	go func() {
		listPath(s3Client, s3path, limit, notifyChan, errChan, stats)
		wg.Done()
	}()

	go func() {
		for err := range errChan { // return last error
			failed = err
		}
	}()

	wg.Wait()
	close(errChan)

	return failed
}

// Given an s3path (e.g., s3://mybucket/myprefix) list files and send to notifyChan
func listPath(s3Client s3iface.S3API, s3path string, limit uint64,
	notifyChan chan *cloudTrailNotification, errChan chan error, stats *Stats) {

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
				stats.NumBytes += (uint64)(*value.Size)
				notifyChan <- &cloudTrailNotification{
					S3Bucket:    &bucket,
					S3ObjectKey: []*string{value.Key},
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

// post message per file as-if it was a CloudTrail notification
func queueNotifications(sqsClient sqsiface.SQSAPI, topicARN string, queueURL *string,
	notifyChan chan *cloudTrailNotification, errChan chan error) {

	for cloudTrailNotification := range notifyChan {
		ctnJSON, err := jsoniter.MarshalToString(cloudTrailNotification)
		if err != nil {
			errChan <- errors.Wrapf(err, "failed to marshal %#v", cloudTrailNotification)
			return
		}

		// make it look like an SNS notification
		snsNotification := events.SNSEntity{
			Type:     "Notification",
			TopicArn: topicARN,
			Message:  ctnJSON,
		}
		message, err := jsoniter.MarshalToString(snsNotification)
		if err != nil {
			errChan <- errors.Wrapf(err, "failed to marshal %#v", snsNotification)
			return
		}

		sendMessageInput := &sqs.SendMessageInput{
			MessageBody: &message,
			QueueUrl:    queueURL,
		}
		_, err = sqsClient.SendMessage(sendMessageInput)
		if err != nil {
			errChan <- errors.Wrapf(err, "failed to send %#v", cloudTrailNotification)
			return
		}
	}
}
