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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

// drop event if the source is not supported
func TestClassifyCloudWatchEventBadSource(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	require.Nil(t, classifyCloudTrailLog(gjson.Parse(`{"eventSource": "aws.nuka", "eventType": "AwsApiCall"}`)))

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.DebugLevel, Message: "dropping event from unsupported source"},
			Context: []zapcore.Field{zap.String("eventSource", "aws.nuka")},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// drop event if it describes a failed API call
func TestClassifyCloudWatchEventErrorCode(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	require.Nil(t, classifyCloudTrailLog(gjson.Parse(`{"errorCode": "AccessDeniedException", "eventSource": "s3.amazonaws.com"}`)))

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

// drop event if its read-only
func TestClassifyCloudWatchEventReadOnly(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	require.Nil(t, classifyCloudTrailLog(
		gjson.Parse(`{"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"}`)),
	)

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.DebugLevel, Message: "s3.amazonaws.com: ignoring read-only event"},
			Context: []zapcore.Field{zap.String("eventName", "ListBuckets")},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// drop event if the service classifier doesn't understand it
func TestClassifyCloudWatchEventClassifyError(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	body :=
		gjson.Parse(`{
				"eventName": "DeleteBucket",
				"recipientAccountId": "111111111111",
				"eventSource":"s3.amazonaws.com"
			}`)
	require.Nil(t, classifyCloudTrailLog(body))

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

// drop event if the account ID is not present
func TestClassifyCloudWatchEventNoRecipientAccountId(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	body := gjson.Parse(`{"eventName": "foo", "eventType" : "AwsApiCall", "eventSource": "s3.amazonaws.com", "requestParameters": {"bucketName": "panther"}}`) //nolint:lll
	changes := classifyCloudTrailLog(body)
	assert.Len(t, changes, 0)

	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.WarnLevel, Message: "dropping event without recipientAccountId field"},
			Context: []zapcore.Field{
				zap.String("eventName", "foo"),
				zap.String("eventSource", "s3.amazonaws.com"),
			},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// drop event if the account ID is not recognized
func TestClassifyCloudWatchEventUnauthorized(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	body := gjson.Parse(`{"recipientAccountId": "foo", "eventType" : "AwsApiCall", "eventSource": "s3.amazonaws.com", "requestParameters": {"bucketName": "panther"}}`) //nolint:lll
	changes := classifyCloudTrailLog(body)
	assert.Len(t, changes, 0)

	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.WarnLevel, Message: "dropping event from unauthorized account"},
			Context: []zapcore.Field{
				zap.String("accountId", "foo"),
				zap.String("eventSource", "s3.amazonaws.com"),
			},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestClassifyCloudWatchEvent(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	body := gjson.Parse(`
	{
		"recipientAccountId": "111111111111",
    	"eventSource": "s3.amazonaws.com",
        "awsRegion": "us-west-2",
        "eventName": "DeleteBucket",
        "eventTime": "2019-08-01T04:43:00Z",
        "requestParameters": {"bucketName": "panther"},
		"userIdentity": {"accountId": "111111111111"}
    }`)
	result := classifyCloudTrailLog(body)
	expected := []*resourceChange{{
		AwsAccountID:  "111111111111",
		Delete:        true,
		EventName:     "DeleteBucket",
		EventTime:     "2019-08-01T04:43:00Z",
		IntegrationID: "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
		ResourceID:    "arn:aws:s3:::panther",
		ResourceType:  schemas.S3BucketSchema,
	}}
	assert.Equal(t, expected, result)
	assert.Empty(t, logs.AllUntimed())
}
