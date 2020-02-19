package forwarder

import (
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *mockDynamoDB) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

var testAlertDedupEvent = &AlertDedupEvent{
	RuleID:              "ruleId",
	DeduplicationString: "dedupString",
	AlertCount:          10,
	CreationTime:        time.Now().UTC(),
	UpdateTime:          time.Now().UTC(),
	EventCount:          100,
}

func init(){
	alertsTable = "alertsTable"
}

// The handler signatures must match those in the LambdaInput struct.
func TestProcess(t *testing.T) {
	ddbMock := &mockDynamoDB{}
	ddbClient = ddbMock

	expectedAlert := &Alert{
		ID:              "ruleId-dedupString-10",
		TimePartition:   "defaultPartition",
		AlertDedupEvent: *testAlertDedupEvent,
	}

	expectedMarshalledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item: expectedMarshalledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	assert.NoError(t, Process(testAlertDedupEvent))
}


// The handler signatures must match those in the LambdaInput struct.
func TestProcessDDBError(t *testing.T) {
	ddbMock := &mockDynamoDB{}
	ddbClient = ddbMock

	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, errors.New("error"))
	assert.Error(t, Process(testAlertDedupEvent))
}
