package processor

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
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

var (
	exampleMetadata = &CloudTrailMetadata{
		region:    "us-west-2",
		accountID: "111111111111",
		eventName: "Example",
	}
)

func exampleChanges() map[string]*resourceChange {
	return make(map[string]*resourceChange)
}

// test the pre-processor
func TestPreProcessCloudTrail(t *testing.T) {
	event := `{ "awsRegion": "us-west-2", "userIdentity": { "accountId" : "111111111111" }, "eventName": "Example" }`
	actual, err := preprocessCloudTrailLog(gjson.Parse(event))
	require.Nil(t, err)
	assert.Equal(t, exampleMetadata, actual)
}

// test the pre-processor on an event with no region
func TestPreProcessCloudTrailFail(t *testing.T) {
	event := `{ "userIdentity": { "accountId" : "111111111111" }, "eventName": "Example" }`
	actual, err := preprocessCloudTrailLog(gjson.Parse(event))
	assert.NotNil(t, err)
	assert.Nil(t, actual)
}

// drop event if its read-only
func TestPreProcessIgnoredEvent(t *testing.T) {
	event := `{ "userIdentity": { "accountId" : "111111111111" }, "eventName": "ListBuckets" }`
	metadata, err := preprocessCloudTrailLog(
		gjson.Parse(event),
	)

	require.Nil(t, err)
	assert.Nil(t, metadata)
}

// drop event if the source is not supported
func TestProcessCloudTrailBadSource(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	event := `{"eventSource": "aws.nuka", "eventType": "AwsApiCall"}`
	require.Nil(t, processCloudTrailLog(gjson.Parse(event), exampleMetadata, exampleChanges()))

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.DebugLevel, Message: "dropping event from unsupported source"},
			Context: []zapcore.Field{zap.String("eventSource", "aws.nuka")},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// drop event if it describes a failed API call
func TestProcessCloudTrailErrorCode(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	event := `{"errorCode": "AccessDeniedException", "eventSource": "s3.amazonaws.com"}`
	require.Nil(t, processCloudTrailLog(gjson.Parse(event), exampleMetadata, exampleChanges()))

	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.DebugLevel, Message: "dropping failed event"},
			Context: []zapcore.Field{
				zap.String("eventSource", "s3.amazonaws.com"),
				zap.String("errorCode", "AccessDeniedException"),
			},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// drop event if the service classifier doesn't understand it
func TestProcessCloudTrailClassifyError(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	event := `
{
"eventName": "DeleteBucket",
"recipientAccountId": "111111111111",
"eventSource":"s3.amazonaws.com"
}`
	metadata := &CloudTrailMetadata{
		region:    "us-west-2",
		accountID: "111111111111",
		eventName: "DeleteBucket",
	}
	require.Nil(t, processCloudTrailLog(gjson.Parse(event), metadata, exampleChanges()))

	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.ErrorLevel, Message: "s3: empty bucket name"},
			Context: []zapcore.Field{
				zap.String("eventName", "DeleteBucket"),
			},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// drop event if the account ID is not recognized
func TestProcessCloudTrailUnauthorized(t *testing.T) {
	accounts = exampleAccounts
	event := `{"eventType" : "AwsApiCall", "eventSource": "s3.amazonaws.com", "requestParameters": {"bucketName": "panther"}}`
	metadata := &CloudTrailMetadata{
		region:    "us-west-2",
		accountID: "222222222222",
		eventName: "Example",
	}
	err := processCloudTrailLog(gjson.Parse(event), metadata, exampleChanges())

	require.NotNil(t, err)
	assert.Equal(t, errors.New("dropping event from unauthorized account 222222222222").Error(), err.Error())
}

func TestProcessCloudTrail(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	event := `
	{
		"recipientAccountId": "111111111111",
    	"eventSource": "s3.amazonaws.com",
        "awsRegion": "us-west-2",
        "eventName": "DeleteBucket",
        "eventTime": "2019-08-01T04:43:00Z",
        "requestParameters": {"bucketName": "panther"},
		"userIdentity": {"accountId": "111111111111"}
    }`
	metadata := &CloudTrailMetadata{
		region:    "us-west-2",
		accountID: "111111111111",
		eventName: "DeleteBucket",
	}
	changeResults := exampleChanges()
	err := processCloudTrailLog(gjson.Parse(event), metadata, changeResults)

	expected := &resourceChange{
		AwsAccountID:  "111111111111",
		Delete:        true,
		EventName:     "DeleteBucket",
		EventTime:     "2019-08-01T04:43:00Z",
		IntegrationID: "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
		ResourceID:    "arn:aws:s3:::panther",
		ResourceType:  schemas.S3BucketSchema,
	}
	expectedLogs := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.InfoLevel, Message: "resource scan required"},
			Context: []zapcore.Field{
				zap.Any("changeDetail", expected),
			},
		},
	}
	require.Nil(t, err)
	assert.Equal(t, expected, changeResults[expected.ResourceID+expected.ResourceType+expected.Region])
	assert.Equal(t, expectedLogs, logs.AllUntimed())
}
