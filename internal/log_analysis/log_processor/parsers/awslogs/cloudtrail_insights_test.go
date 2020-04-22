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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestCloudTrailInsightParser(t *testing.T) {
	//nolint:lll
	log := `{
		"Records": [
			{
				"eventVersion": "1.07",
				"eventTime": "2019-10-17T10:05:00Z",
				"awsRegion": "us-east-1",
				"eventID": "aab985f2-3a56-48cc-a8a5-e0af77606f5f",
				"eventType": "AwsCloudTrailInsight",
				"recipientAccountId": "123456789012",
				"sharedEventID": "12edc982-3348-4794-83d3-a3db26525049",
				"insightDetails": {
					"state": "Start",
					"eventSource": "ssm.amazonaws.com",
					"eventName": "UpdateInstanceAssociationStatus",
					"insightType": "ApiCallRateInsight",
					"insightContext": {
						"statistics": {
							"baseline": {
								"average": 1.7561507937
							},
							"insight": {
								"average": 50.1
							}
						}
					}
				},
				"eventCategory": "Insight"
			},
			{
				"eventVersion": "1.07",
				"eventTime": "2019-10-17T10:13:00Z",
				"awsRegion": "us-east-1",
				"eventID": "ce7b8ac1-3f89-4dae-8d2a-6560e32f591a",
				"eventType": "AwsCloudTrailInsight",
				"recipientAccountId": "123456789012",
				"sharedEventID": "12edc982-3348-4794-83d3-a3db26525049",
				"insightDetails": {
					"state": "End",
					"eventSource": "ssm.amazonaws.com",
					"eventName": "UpdateInstanceAssociationStatus",
					"insightType": "ApiCallRateInsight",
					"insightContext": {
						"statistics": {
							"baseline": {
								"average": 1.7561507937
							},
							"insight": {
								"average": 50
							},
							"insightDuration": 8
						}
					}
				},
				"eventCategory": "Insight"
			}
		]
	}`

	expectedDateStart := time.Date(2019, 10, 17, 10, 5, 0, 0, time.UTC)
	expectedDateEnd := time.Date(2019, 10, 17, 10, 13, 0, 0, time.UTC)
	expectedEventStart := &CloudTrailInsight{
		EventVersion:       aws.String("1.07"),
		EventTime:          (*timestamp.RFC3339)(&expectedDateStart),
		AWSRegion:          aws.String("us-east-1"),
		EventID:            aws.String("aab985f2-3a56-48cc-a8a5-e0af77606f5f"),
		EventType:          aws.String("AwsCloudTrailInsight"),
		RecipientAccountID: aws.String("123456789012"),
		SharedEventID:      aws.String("12edc982-3348-4794-83d3-a3db26525049"),
		InsightDetails: &InsightDetails{
			State:       aws.String("Start"),
			EventSource: aws.String("ssm.amazonaws.com"),
			EventName:   aws.String("UpdateInstanceAssociationStatus"),
			InsightType: aws.String("ApiCallRateInsight"),
			InsightContext: &InsightContext{
				Statistics: &InsightStatistics{
					Baseline: &InsightAverage{
						Average: aws.Float64(1.7561507937),
					},
					Insight: &InsightAverage{
						Average: aws.Float64(50.1),
					},
				},
			},
		},
		EventCategory: aws.String("Insight"),
	}
	expectedEventEnd := &CloudTrailInsight{
		EventVersion:       aws.String("1.07"),
		EventTime:          (*timestamp.RFC3339)(&expectedDateEnd),
		AWSRegion:          aws.String("us-east-1"),
		EventID:            aws.String("ce7b8ac1-3f89-4dae-8d2a-6560e32f591a"),
		EventType:          aws.String("AwsCloudTrailInsight"),
		RecipientAccountID: aws.String("123456789012"),
		SharedEventID:      aws.String("12edc982-3348-4794-83d3-a3db26525049"),
		InsightDetails: &InsightDetails{
			State:       aws.String("End"),
			EventSource: aws.String("ssm.amazonaws.com"),
			EventName:   aws.String("UpdateInstanceAssociationStatus"),
			InsightType: aws.String("ApiCallRateInsight"),
			InsightContext: &InsightContext{
				Statistics: &InsightStatistics{
					Baseline: &InsightAverage{
						Average: aws.Float64(1.7561507937),
					},
					Insight: &InsightAverage{
						Average: aws.Float64(50),
					},
					InsightDuration: aws.Float32(8),
				},
			},
		},
		EventCategory: aws.String("Insight"),
	}

	// panther fields
	expectedEventStart.PantherLogType = aws.String("AWS.CloudTrailInsight")
	expectedEventStart.PantherEventTime = (*timestamp.RFC3339)(&expectedDateStart)
	expectedEventStart.AppendAnyAWSAccountIds("123456789012")
	expectedEventEnd.PantherLogType = aws.String("AWS.CloudTrailInsight")
	expectedEventEnd.PantherEventTime = (*timestamp.RFC3339)(&expectedDateEnd)
	expectedEventEnd.AppendAnyAWSAccountIds("123456789012")
	expectedEventEnd.SetEvent(expectedEventEnd)
	expectedEventStart.SetEvent(expectedEventStart)
	testutil.CheckPantherParser(t, log, &CloudTrailInsightParser{}, expectedEventStart.Log(), expectedEventEnd.Log())
}

func TestCloudTrailInsightLogType(t *testing.T) {
	parser := &CloudTrailInsightParser{}
	require.Equal(t, "AWS.CloudTrailInsight", parser.LogType())
}
