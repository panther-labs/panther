package testutils

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/eventbridge/eventbridgeiface"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/firehose/firehoseiface"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/mock"
)

type S3UploaderMock struct {
	s3manageriface.UploaderAPI
	mock.Mock
}

func (m *S3UploaderMock) Upload(input *s3manager.UploadInput, f ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error) {
	args := m.Called(input, f)
	return args.Get(0).(*s3manager.UploadOutput), args.Error(1)
}

type S3Mock struct {
	s3iface.S3API
	mock.Mock
}

func (m *S3Mock) MaxRetries() int {
	args := m.Called()
	return args.Int(0)
}

func (m *S3Mock) DeleteObjects(input *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*s3.DeleteObjectsOutput), args.Error(1)
}

func (m *S3Mock) GetObject(input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

func (m *S3Mock) GetObjectWithContext(ctx aws.Context, input *s3.GetObjectInput, options ...request.Option) (*s3.GetObjectOutput, error) {
	args := m.Called(ctx, input, options)
	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

func (m *S3Mock) GetBucketLocation(input *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*s3.GetBucketLocationOutput), args.Error(1)
}

func (m *S3Mock) ListObjectsV2Pages(input *s3.ListObjectsV2Input, f func(page *s3.ListObjectsV2Output, morePages bool) bool) error {
	args := m.Called(input, f)
	f(args.Get(0).(*s3.ListObjectsV2Output), false)
	return args.Error(1)
}

func (m *S3Mock) ListObjectsV2PagesWithContext(ctx aws.Context, input *s3.ListObjectsV2Input,
	f func(page *s3.ListObjectsV2Output, morePages bool) bool, options ...request.Option) error {

	args := m.Called(ctx, input, f, options)
	f(args.Get(0).(*s3.ListObjectsV2Output), false)
	return args.Error(1)
}

func (m *S3Mock) SelectObjectContent(input *s3.SelectObjectContentInput) (*s3.SelectObjectContentOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*s3.SelectObjectContentOutput), args.Error(1)
}

func (m *S3Mock) SelectObjectContentWithContext(
	ctx aws.Context,
	input *s3.SelectObjectContentInput,
	options ...request.Option) (*s3.SelectObjectContentOutput, error) {

	args := m.Called(ctx, input, options)
	return args.Get(0).(*s3.SelectObjectContentOutput), args.Error(1)
}

type S3SelectStreamReaderMock struct {
	s3.SelectObjectContentEventStreamReader
	mock.Mock
}

func (m *S3SelectStreamReaderMock) Events() <-chan s3.SelectObjectContentEventStreamEvent {
	args := m.Called()
	return args.Get(0).(<-chan s3.SelectObjectContentEventStreamEvent)
}

func (m *S3SelectStreamReaderMock) Err() error {
	args := m.Called()
	return args.Error(0)
}

type LambdaMock struct {
	lambdaiface.LambdaAPI
	mock.Mock
}

func (m *LambdaMock) Invoke(input *lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*lambda.InvokeOutput), args.Error(1)
}

func (m *LambdaMock) InvokeWithContext(
	ctx aws.Context,
	input *lambda.InvokeInput,
	options ...request.Option) (*lambda.InvokeOutput, error) {

	args := m.Called(ctx, input, options)
	return args.Get(0).(*lambda.InvokeOutput), args.Error(1)
}

func (m *LambdaMock) CreateEventSourceMapping(
	input *lambda.CreateEventSourceMappingInput) (*lambda.EventSourceMappingConfiguration, error) {

	args := m.Called(input)
	return args.Get(0).(*lambda.EventSourceMappingConfiguration), args.Error(1)
}

func (m *LambdaMock) ListEventSourceMappings(input *lambda.ListEventSourceMappingsInput) (*lambda.ListEventSourceMappingsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*lambda.ListEventSourceMappingsOutput), args.Error(1)
}

func (m *LambdaMock) DeleteEventSourceMapping(
	input *lambda.DeleteEventSourceMappingInput) (*lambda.EventSourceMappingConfiguration, error) {

	args := m.Called(input)
	return args.Get(0).(*lambda.EventSourceMappingConfiguration), args.Error(1)
}

type DynamoDBMock struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *DynamoDBMock) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

func (m *DynamoDBMock) UpdateItem(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.UpdateItemOutput), args.Error(1)
}

func (m *DynamoDBMock) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}

func (m *DynamoDBMock) DeleteItem(input *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.DeleteItemOutput), args.Error(1)
}

func (m *DynamoDBMock) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.QueryOutput), args.Error(1)
}

func (m *DynamoDBMock) Scan(input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.ScanOutput), args.Error(1)
}

type SqsMock struct {
	sqsiface.SQSAPI
	mock.Mock
}

// nolint (golint)
func (m *SqsMock) GetQueueUrl(input *sqs.GetQueueUrlInput) (*sqs.GetQueueUrlOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.GetQueueUrlOutput), args.Error(1)
}

func (m *SqsMock) SendMessage(input *sqs.SendMessageInput) (*sqs.SendMessageOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SendMessageOutput), args.Error(1)
}

func (m *SqsMock) SendMessageWithContext(
	ctx context.Context,
	input *sqs.SendMessageInput,
	_ ...request.Option,
) (*sqs.SendMessageOutput, error) {

	args := m.Called(ctx, input)
	return args.Get(0).(*sqs.SendMessageOutput), args.Error(1)
}

func (m *SqsMock) SendMessageBatch(input *sqs.SendMessageBatchInput) (*sqs.SendMessageBatchOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SendMessageBatchOutput), args.Error(1)
}

func (m *SqsMock) SetQueueAttributes(input *sqs.SetQueueAttributesInput) (*sqs.SetQueueAttributesOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SetQueueAttributesOutput), args.Error(1)
}

func (m *SqsMock) GetQueueAttributes(input *sqs.GetQueueAttributesInput) (*sqs.GetQueueAttributesOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.GetQueueAttributesOutput), args.Error(1)
}

func (m *SqsMock) GetQueueAttributesWithContext(
	ctx aws.Context,
	input *sqs.GetQueueAttributesInput,
	options ...request.Option) (*sqs.GetQueueAttributesOutput, error) {

	args := m.Called(ctx, input, options)
	return args.Get(0).(*sqs.GetQueueAttributesOutput), args.Error(1)
}

func (m *SqsMock) DeleteMessageBatch(input *sqs.DeleteMessageBatchInput) (*sqs.DeleteMessageBatchOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.DeleteMessageBatchOutput), args.Error(1)
}

func (m *SqsMock) ReceiveMessage(input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.ReceiveMessageOutput), args.Error(1)
}

func (m *SqsMock) ReceiveMessageWithContext(
	ctx aws.Context,
	input *sqs.ReceiveMessageInput,
	options ...request.Option) (*sqs.ReceiveMessageOutput, error) {

	args := m.Called(ctx, input, options)
	return args.Get(0).(*sqs.ReceiveMessageOutput), args.Error(1)
}

func (m *SqsMock) CreateQueue(input *sqs.CreateQueueInput) (*sqs.CreateQueueOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.CreateQueueOutput), args.Error(1)
}

func (m *SqsMock) DeleteQueue(input *sqs.DeleteQueueInput) (*sqs.DeleteQueueOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.DeleteQueueOutput), args.Error(1)
}

type EventBridgeMock struct {
	eventbridgeiface.EventBridgeAPI
	mock.Mock
}

func (m *EventBridgeMock) ListEventBuses(input *eventbridge.ListEventBusesInput) (*eventbridge.ListEventBusesOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*eventbridge.ListEventBusesOutput), args.Error(1)
}

func (m *EventBridgeMock) PutTargets(input *eventbridge.PutTargetsInput) (*eventbridge.PutTargetsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*eventbridge.PutTargetsOutput), args.Error(1)
}

func (m *EventBridgeMock) RemoveTargets(input *eventbridge.RemoveTargetsInput) (*eventbridge.RemoveTargetsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*eventbridge.RemoveTargetsOutput), args.Error(1)
}

func (m *EventBridgeMock) PutRule(input *eventbridge.PutRuleInput) (*eventbridge.PutRuleOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*eventbridge.PutRuleOutput), args.Error(1)
}

func (m *EventBridgeMock) DeleteRule(input *eventbridge.DeleteRuleInput) (*eventbridge.DeleteRuleOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*eventbridge.DeleteRuleOutput), args.Error(1)
}

type GlueMock struct {
	glueiface.GlueAPI
	mock.Mock
	LogTables []*glue.TableData
}

func (m *GlueMock) CreateDatabase(input *glue.CreateDatabaseInput) (*glue.CreateDatabaseOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.CreateDatabaseOutput), args.Error(1)
}

func (m *GlueMock) CreateDatabaseWithContext(
	ctx context.Context,
	input *glue.CreateDatabaseInput,
	options ...request.Option,
) (*glue.CreateDatabaseOutput, error) {

	arguments := []interface{}{ctx, input}
	for _, option := range options {
		arguments = append(arguments, option)
	}
	results := m.Called(arguments...)
	return results.Get(0).(*glue.CreateDatabaseOutput), results.Error(1)
}

func (m *GlueMock) CreateTable(input *glue.CreateTableInput) (*glue.CreateTableOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.CreateTableOutput), args.Error(1)
}
func (m *GlueMock) CreateTableWithContext(ctx context.Context,
	input *glue.CreateTableInput, _ ...request.Option) (*glue.CreateTableOutput, error) {

	args := m.Called(ctx, input)
	return args.Get(0).(*glue.CreateTableOutput), args.Error(1)
}

func (m *GlueMock) GetTable(input *glue.GetTableInput) (*glue.GetTableOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.GetTableOutput), args.Error(1)
}

func (m *GlueMock) DeleteTable(input *glue.DeleteTableInput) (*glue.DeleteTableOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.DeleteTableOutput), args.Error(1)
}

func (m *GlueMock) CreatePartition(input *glue.CreatePartitionInput) (*glue.CreatePartitionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.CreatePartitionOutput), args.Error(1)
}

func (m *GlueMock) GetPartition(input *glue.GetPartitionInput) (*glue.GetPartitionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.GetPartitionOutput), args.Error(1)
}

func (m *GlueMock) GetPartitions(input *glue.GetPartitionsInput) (*glue.GetPartitionsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.GetPartitionsOutput), args.Error(1)
}

func (m *GlueMock) UpdatePartition(input *glue.UpdatePartitionInput) (*glue.UpdatePartitionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.UpdatePartitionOutput), args.Error(1)
}

// nolint:lll
func (m *GlueMock) GetTablesPagesWithContext(
	ctx aws.Context,
	input *glue.GetTablesInput,
	scan func(page *glue.GetTablesOutput, isLast bool) bool,
	_ ...request.Option,
) error {

	args := m.Called(ctx, input, scan)
	scan(&glue.GetTablesOutput{
		TableList: m.LogTables,
	}, true)
	return args.Error(0)
}

type AthenaMock struct {
	athenaiface.AthenaAPI
	mock.Mock
}

func (m *AthenaMock) StartQueryExecution(input *athena.StartQueryExecutionInput) (*athena.StartQueryExecutionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*athena.StartQueryExecutionOutput), args.Error(1)
}

func (m *AthenaMock) GetQueryExecution(input *athena.GetQueryExecutionInput) (*athena.GetQueryExecutionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*athena.GetQueryExecutionOutput), args.Error(1)
}

func (m *AthenaMock) GetQueryResults(input *athena.GetQueryResultsInput) (*athena.GetQueryResultsOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*athena.GetQueryResultsOutput), args.Error(1)
}

func (m *AthenaMock) ListTableMetadataPagesWithContext(ctx aws.Context, input *athena.ListTableMetadataInput,
	f func(*athena.ListTableMetadataOutput, bool) bool, option ...request.Option) error {

	args := m.Called(ctx, input, f)
	return args.Error(0)
}

type SnsMock struct {
	snsiface.SNSAPI
	mock.Mock
}

func (m *SnsMock) Publish(input *sns.PublishInput) (*sns.PublishOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sns.PublishOutput), args.Error(1)
}

func (m *SnsMock) PublishWithContext(ctx context.Context, input *sns.PublishInput, options ...request.Option) (*sns.PublishOutput, error) {
	args := m.Called(ctx, input, options)
	return args.Get(0).(*sns.PublishOutput), args.Error(1)
}

func (m *SnsMock) ConfirmSubscription(input *sns.ConfirmSubscriptionInput) (*sns.ConfirmSubscriptionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sns.ConfirmSubscriptionOutput), args.Error(1)
}

type FirehoseMock struct {
	firehoseiface.FirehoseAPI
	mock.Mock
}

func (m *FirehoseMock) PutRecordBatchWithContext(
	ctx aws.Context,
	input *firehose.PutRecordBatchInput,
	options ...request.Option) (*firehose.PutRecordBatchOutput, error) {

	args := m.Called(ctx, input, options)
	return args.Get(0).(*firehose.PutRecordBatchOutput), args.Error(1)
}
