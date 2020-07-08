package awslogs

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
	"testing"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
)

func TestCloudWatchEventEC2Instance(t *testing.T) {
	log := `
{
  "version": "0",
  "id": "6a7e8feb-b491-4cf7-a9f1-bf3703467718",
  "detail-type": "EC2 Instance State-change Notification",
  "source": "aws.ec2",
  "account": "111122223333",
  "time": "2017-12-22T18:43:48Z",
  "region": "us-west-1",
  "resources": [
    "arn:aws:ec2:us-west-1:123456789012:instance/ i-1234567890abcdef0"
  ],
  "detail": {
    "instance-id": " i-1234567890abcdef0",
    "state": "terminated"
  }
}`
	tm := time.Date(2017, 12, 22, 18, 43, 48, 0, time.UTC)
	expectedEvent := &CloudWatchEvent{
		ID:         box.String("6a7e8feb-b491-4cf7-a9f1-bf3703467718"),
		Time:       (*timestamp.RFC3339)(&tm),
		Version:    box.String("0"),
		DetailType: box.String("EC2 Instance State-change Notification"),
		Source:     box.String("aws.ec2"),
		Account:    box.String("111122223333"),
		Region:     box.String("us-west-1"),
		Resources:  []string{"arn:aws:ec2:us-west-1:123456789012:instance/ i-1234567890abcdef0"},
		Detail:     testutil.NewRawMessage(`{"instance-id": " i-1234567890abcdef0","state": "terminated"}`),
	}
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&tm)
	expectedEvent.PantherLogType = box.String(TypeCloudWatchEvents)
	expectedEvent.SetEvent(expectedEvent)
	expectedEvent.AppendAnyAWSARNs("arn:aws:ec2:us-west-1:123456789012:instance/ i-1234567890abcdef0")
	expectedEvent.AppendAnyAWSAccountIds("111122223333")
	testutil.CheckPantherParser(t, log, (&CloudWatchEventParser{}).New(), &expectedEvent.PantherLog)
}

func TestCloudWatchEventCloudTrail(t *testing.T) {
	logDetail := `
{
        "eventVersion": "1.03",
        "userIdentity": {
            "type": "Root",
            "principalId": "123456789012",
            "arn": "arn:aws:iam::123456789012:root",
            "accountId": "123456789012",
            "sessionContext": {
                "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate": "2016-02-20T01:05:59Z"
                }
            }
        },
        "eventTime": "2017-12-22T18:43:48Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "CreateBucket",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "100.100.100.100",
        "userAgent": "[S3Console/0.4]",
        "requestParameters": {
            "bucketName": "bucket-test-iad"
        },
        "responseElements": null,
        "requestID": "9D767BCC3B4E7487",
        "eventID": "24ba271e-d595-4e66-a7fd-9c16cbf8abae",
        "eventType": "AwsApiCall"
    }

`
	log := `
{
    "version": "0",
    "id": "36eb8523-97d0-4518-b33d-ee3579ff19f0",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.s3",
    "account": "123456789012",
    "time": "2017-12-22T18:43:48Z",
    "region": "us-east-1",
    "resources": [],
    "detail": %s
}
`
	tm := time.Date(2017, 12, 22, 18, 43, 48, 0, time.UTC)
	expectedEvent := &CloudWatchEvent{
		ID:         box.String("36eb8523-97d0-4518-b33d-ee3579ff19f0"),
		Time:       (*timestamp.RFC3339)(&tm),
		Version:    box.String("0"),
		DetailType: box.String("AWS API Call via CloudTrail"),
		Source:     box.String("aws.s3"),
		Account:    box.String("123456789012"),
		Region:     box.String("us-east-1"),
		Resources:  []string{},
		Detail:     testutil.NewRawMessage(logDetail),
	}
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&tm)
	expectedEvent.PantherLogType = box.String(TypeCloudWatchEvents)
	expectedEvent.SetEvent(expectedEvent)
	expectedEvent.AppendAnyAWSAccountIds("123456789012")
	expectedEvent.AppendAnyAWSARNs("arn:aws:iam::123456789012:root")
	testutil.CheckPantherParser(t, fmt.Sprintf(log, logDetail), (&CloudWatchEventParser{}).New(), &expectedEvent.PantherLog)
}
