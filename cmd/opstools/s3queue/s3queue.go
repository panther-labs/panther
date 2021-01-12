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
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/cmd/opstools/s3list"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/awsretry"
)

const (
	maxRetries = 7

	// account is added for sqs messages because the log processor expects it but the arn itself does not need to be real
	fakeTopicArnTemplate = "arn:aws:sns:us-east-1:%s:panther-fake-s3queue-topic"

	notifyChanDepth = 1000
)

type Input struct {
	DriverInput
	Session  *session.Session
	S3Path   string
	S3Region string
	Limit    uint64
	Loop     bool
	Stats    s3list.Stats // passed in so we can get stats if canceled
}

type DriverInput struct {
	Logger         *zap.SugaredLogger
	Account        string
	QueueName      string
	Concurrency    int
	FilesPerSecond float64       // if non-zero,  attempt to send at this rate
	Duration       time.Duration // if set, stop after this much elapsed time
}

func S3Queue(ctx context.Context, input *Input) (err error) {
	clientsSession := input.Session.Copy(request.WithRetryer(aws.NewConfig().WithMaxRetries(maxRetries),
		awsretry.NewConnectionErrRetryer(maxRetries)))
	s3Client := s3.New(clientsSession.Copy(&aws.Config{Region: &input.S3Region}))
	sqsClient := sqs.New(clientsSession)
	return s3Queue(ctx, s3Client, sqsClient, input)
}

func s3Queue(ctx context.Context, s3Client s3iface.S3API, sqsClient sqsiface.SQSAPI, input *Input) (err error) {
	driver, err := NewDriver(ctx, sqsClient, &input.DriverInput)
	if err != nil {
		return err
	}

	err = s3list.ListPath(driver.workerCtx, &s3list.Input{
		Logger:   input.Logger,
		S3Client: s3Client,
		S3Path:   input.S3Path,
		Limit:    input.Limit,
		Loop:     input.Loop,
		Write:    func(event *events.S3Event) { driver.Write(event) },
		Done:     func() { driver.Done() },
		Stats:    &input.Stats,
	})
	if err != nil { // ListPath() will call Done() function which will close notifyChan() on return causing workers to exit
		return err
	}

	return driver.Wait() // returns any error from workers
}

type Driver struct {
	logger      *zap.SugaredLogger
	sqsClient   sqsiface.SQSAPI
	queueURL    *string
	topicARN    string
	notifyChan  chan *events.S3Event
	workerGroup *errgroup.Group
	workerCtx   context.Context

	// used for pacing at a fixed rate
	delay time.Duration

	// set if we have set a deadline
	deadlineCancel context.CancelFunc
}

func NewDriver(ctx context.Context, sqsClient sqsiface.SQSAPI, input *DriverInput) (*Driver, error) {
	if input.Concurrency <= 0 {
		return nil, errors.Errorf("concurrency must be > 0: %d", input.Concurrency)
	}

	queueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &input.QueueName,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "could not get queue url for %s", input.QueueName)
	}

	// the account id is taken from this arn to assume the role for reading in the log processor
	topicARN := fmt.Sprintf(fakeTopicArnTemplate, input.Account)

	notifyChan := make(chan *events.S3Event, notifyChanDepth)

	// optional deadline
	var deadlineCancel context.CancelFunc
	if input.Duration > 0 {
		ctx, deadlineCancel = context.WithDeadline(ctx, time.Now().Add(input.Duration))
	}

	workerGroup, workerCtx := errgroup.WithContext(ctx)

	driver := &Driver{
		logger:         input.Logger,
		sqsClient:      sqsClient,
		queueURL:       queueURL.QueueUrl,
		topicARN:       topicARN,
		notifyChan:     notifyChan,
		workerGroup:    workerGroup,
		workerCtx:      workerCtx,
		deadlineCancel: deadlineCancel,
	}

	if input.FilesPerSecond > 0.0 {
		driver.delay = time.Duration((float64(time.Second) / input.FilesPerSecond) * float64(input.Concurrency))
	}

	for i := 0; i < input.Concurrency; i++ {
		workerGroup.Go(func() error {
			return queueNotifications(driver)
		})
	}

	return driver, nil
}

func (d *Driver) Write(event *events.S3Event) {
	d.notifyChan <- event
}

func (d *Driver) Done() {
	close(d.notifyChan)
}

func (d *Driver) Wait() error {
	if d.deadlineCancel != nil {
		defer d.deadlineCancel() // signal ctx and parent
	}
	return d.workerGroup.Wait() // returns any error from workers
}

// post message per file as-if it was an S3 notification
func queueNotifications(driver *Driver) (failed error) {
	sendMessageBatchInput := &sqs.SendMessageBatchInput{
		QueueUrl: driver.queueURL,
	}

	// we have 1 file per notification to limit blast radius in case of failure.
	const (
		batchTimeout = time.Minute
		batchSize    = 10
	)

	var i, sendTime, avgSendTime time.Duration = 1, 0, 0 // used to calc avg send time

	for s3Notification := range driver.notifyChan {
		if failed != nil { // drain channel
			continue
		}

		select {
		case <-driver.workerCtx.Done(): // signal we were aborted
			failed = driver.workerCtx.Err()
			continue
		default: // non blocking
		}

		// the driver.delay is calculated as-if there was no overhead to send, need to adjust a bit
		delay := driver.delay
		if delay > 0 {
			time.Sleep(delay - avgSendTime) // used for pacing
		}

		startSend := time.Now() // used to estimate avg time to send message

		driver.logger.Debugf("sending s3://%s/%s (%d bytes) to SQS",
			s3Notification.Records[0].S3.Bucket.Name,
			s3Notification.Records[0].S3.Object.Key,
			s3Notification.Records[0].S3.Object.Size)

		ctnJSON, err := jsoniter.MarshalToString(s3Notification)
		if err != nil {
			failed = errors.Wrapf(err, "failed to marshal %#v", s3Notification)
			continue
		}

		// make it look like an SNS notification
		snsNotification := events.SNSEntity{
			Type:     "Notification",
			TopicArn: driver.topicARN, // this is needed by the log processor to get account associated with the S3 object
			Message:  ctnJSON,
		}
		message, err := jsoniter.MarshalToString(snsNotification)
		if err != nil {
			failed = errors.Wrapf(err, "failed to marshal %#v", snsNotification)
			continue
		}

		sendMessageBatchInput.Entries = append(sendMessageBatchInput.Entries, &sqs.SendMessageBatchRequestEntry{
			Id:          aws.String(strconv.Itoa(len(sendMessageBatchInput.Entries))),
			MessageBody: &message,
		})
		if len(sendMessageBatchInput.Entries)%batchSize == 0 {
			_, err = sqsbatch.SendMessageBatch(driver.sqsClient, batchTimeout, sendMessageBatchInput)
			if err != nil {
				failed = errors.Wrapf(err, "failed to send %#v", sendMessageBatchInput)
				continue
			}
			sendMessageBatchInput.Entries = make([]*sqs.SendMessageBatchRequestEntry, 0, batchSize) // reset
		}

		// send time calculations
		sendTime += time.Since(startSend)
		i++
		if i%batchSize == 0 { // only update avg after a full send to smooth
			avgSendTime = sendTime / i
		}
	}

	// send remaining
	if failed == nil && len(sendMessageBatchInput.Entries) > 0 {
		_, err := sqsbatch.SendMessageBatch(driver.sqsClient, batchTimeout, sendMessageBatchInput)
		if err != nil {
			failed = errors.Wrapf(err, "failed to send %#v", sendMessageBatchInput)
		}
	}

	return failed
}
