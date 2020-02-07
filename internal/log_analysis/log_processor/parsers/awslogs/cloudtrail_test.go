package awslogs

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestCloudTrailLogGenerateDataKey(t *testing.T) {
	//nolint:lll
	log := `{"Records": [{"eventVersion":"1.05","userIdentity":{"type":"AWSService","invokedBy":"cloudtrail.amazonaws.com"},"eventTime":"2018-08-26T14:17:23Z","eventSource":"kms.amazonaws.com","eventName":"GenerateDataKey","awsRegion":"us-west-2","sourceIPAddress":"cloudtrail.amazonaws.com","userAgent":"cloudtrail.amazonaws.com","requestParameters":{"keySpec":"AES_256","encryptionContext":{"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail","aws:s3:arn":"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"},"keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"},"responseElements":null,"requestID":"3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086","eventID":"7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2","readOnly":true,"resources":[{"ARN":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0","accountId":"888888888888","type":"AWS::KMS::Key"}],"eventType":"AwsApiCall","recipientAccountId":"888888888888","sharedEventID":"238c190c-1a30-4756-8e08-19fc36ad1b9f"}]}`

	expectedDate := time.Unix(1535293043, 0).In(time.UTC)
	expectedEvent := &CloudTrail{
		EventVersion: aws.String("1.05"),
		UserIdentity: &CloudTrailUserIdentity{
			Type:      aws.String("AWSService"),
			InvokedBy: aws.String("cloudtrail.amazonaws.com"),
		},
		EventTime:       (*timestamp.RFC3339)(&expectedDate),
		EventSource:     aws.String("kms.amazonaws.com"),
		EventName:       aws.String("GenerateDataKey"),
		AWSRegion:       aws.String("us-west-2"),
		SourceIPAddress: aws.String("cloudtrail.amazonaws.com"),
		UserAgent:       aws.String("cloudtrail.amazonaws.com"),
		RequestID:       aws.String("3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086"),
		EventID:         aws.String("7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2"),
		ReadOnly:        aws.Bool(true),
		Resources: []CloudTrailResources{
			{
				ARN:       aws.String("arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"),
				AccountID: aws.String("888888888888"),
				Type:      aws.String("AWS::KMS::Key"),
			},
		},
		EventType:          aws.String("AwsApiCall"),
		RecipientAccountID: aws.String("888888888888"),
		SharedEventID:      aws.String("238c190c-1a30-4756-8e08-19fc36ad1b9f"),
		//nolint:lll
		RequestParameters: newRawMessage(`{"keySpec":"AES_256","encryptionContext":{"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail","aws:s3:arn":"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"},"keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"}`),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.CloudTrail")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDate)
	expectedEvent.AppendAnyAWSARNs("arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0",
		"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail",
		//nolint:lll
		"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz")
	expectedEvent.AppendAnyAWSAccountIds("888888888888")

	checkCloudTrailLog(t, log, []*CloudTrail{expectedEvent})
}

func TestCloudTrailLogType(t *testing.T) {
	parser := &CloudTrailParser{}
	require.Equal(t, "AWS.CloudTrail", parser.LogType())
}

func checkCloudTrailLog(t *testing.T, log string, expectedEvents []*CloudTrail) {
	parser := &CloudTrailParser{}
	events := parser.Parse(log)

	require.Equal(t, len(expectedEvents), len(events))

	// panther fields
	for i, expectedEvent := range expectedEvents {
		// rowid changes each time
		event := events[i].(*CloudTrail)
		require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
		event.PantherRowID = expectedEvent.PantherRowID
	}

	for i := range events {
		require.Equal(t, expectedEvents[i], events[i].(*CloudTrail))
	}
}
