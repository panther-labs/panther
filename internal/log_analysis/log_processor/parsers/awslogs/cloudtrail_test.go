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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
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

func TestCloudTrailLogDecrypt(t *testing.T) {
	//nolint:lll
	log := `{"Records": [{"eventVersion":"1.05","userIdentity":{"type":"AssumedRole","principalId":"AROAQXSBWDWTDYDZAXXXX:panther-log-processor","arn":"arn:aws:sts::888888888888:assumed-role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX/panther-log-processor","accountId":"888888888888","accessKeyId":"ASIAQXSBWDWTC6ITXXXX","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAQXSBWDWTDYDZAXXXX","arn":"arn:aws:iam::888888888888:role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX","accountId":"888888888888","userName":"panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX"},"attributes":{"mfaAuthenticated":"false","creationDate":"2018-02-20T13:13:35Z"}}},"eventTime":"2018-08-26T14:17:23Z","eventSource":"kms.amazonaws.com","eventName":"Decrypt","awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4","userAgent":"aws-internal/3 aws-sdk-java/1.11.706 Linux/4.14.77-70.59.amzn1.x86_64 OpenJDK_64-Bit_Server_VM/25.242-b08 java/1.8.0_242 vendor/Oracle_Corporation","requestParameters":{"encryptionContext":{"aws:lambda:FunctionArn":"arn:aws:lambda:us-east-1:888888888888:function:panther-log-processor"},"encryptionAlgorithm":"SYMMETRIC_DEFAULT"},"responseElements":null,"requestID":"3c5a008c-80d5-491a-bf76-0cac924f6ebb","eventID":"1852a808-86e8-4b4c-9d4d-01a85b6a39cd","readOnly":true,"resources":[{"accountId":"888888888888","type":"AWS::KMS::Key","ARN":"arn:aws:kms:us-east-1:888888888888:key/90be6df2-db60-4237-ad9b-a49260XXXXX"}],"eventType":"AwsApiCall"}]}`

	expectedDate := time.Unix(1535293043, 0).In(time.UTC)
	expectedEvent := &CloudTrail{
		EventVersion: aws.String("1.05"),
		UserIdentity: &CloudTrailUserIdentity{
			Type:        aws.String("AssumedRole"),
			PrincipalID: aws.String("AROAQXSBWDWTDYDZAXXXX:panther-log-processor"),
			//nolint:lll
			ARN:         aws.String("arn:aws:sts::888888888888:assumed-role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX/panther-log-processor"),
			AccountID:   aws.String("888888888888"),
			AccessKeyID: aws.String("ASIAQXSBWDWTC6ITXXXX"),
			SessionContext: &CloudTrailSessionContext{
				Attributes: &CloudTrailSessionContextAttributes{
					MfaAuthenticated: aws.String("false"),
					CreationDate:     aws.String("2018-02-20T13:13:35Z"),
				},
				SessionIssuer: &CloudTrailSessionContextSessionIssuer{
					Type:        aws.String("Role"),
					PrincipalID: aws.String("AROAQXSBWDWTDYDZAXXXX"),
					Arn:         aws.String("arn:aws:iam::888888888888:role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX"),
					AccountID:   aws.String("888888888888"),
					Username:    aws.String("panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX"),
				},
			},
		},
		EventTime:       (*timestamp.RFC3339)(&expectedDate),
		EventSource:     aws.String("kms.amazonaws.com"),
		EventName:       aws.String("Decrypt"),
		AWSRegion:       aws.String("us-east-1"),
		SourceIPAddress: aws.String("1.2.3.4"),
		//nolint:lll
		UserAgent: aws.String("aws-internal/3 aws-sdk-java/1.11.706 Linux/4.14.77-70.59.amzn1.x86_64 OpenJDK_64-Bit_Server_VM/25.242-b08 java/1.8.0_242 vendor/Oracle_Corporation"),
		RequestID: aws.String("3c5a008c-80d5-491a-bf76-0cac924f6ebb"),
		EventID:   aws.String("1852a808-86e8-4b4c-9d4d-01a85b6a39cd"),
		ReadOnly:  aws.Bool(true),
		Resources: []CloudTrailResources{
			{
				ARN:       aws.String("arn:aws:kms:us-east-1:888888888888:key/90be6df2-db60-4237-ad9b-a49260XXXXX"),
				AccountID: aws.String("888888888888"),
				Type:      aws.String("AWS::KMS::Key"),
			},
		},
		EventType: aws.String("AwsApiCall"),
		//nolint:lll
		RequestParameters: newRawMessage(`{"encryptionContext":{"aws:lambda:FunctionArn":"arn:aws:lambda:us-east-1:888888888888:function:panther-log-processor"},"encryptionAlgorithm":"SYMMETRIC_DEFAULT"}`),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.CloudTrail")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDate)
	expectedEvent.AppendAnyAWSARNs("arn:aws:kms:us-east-1:888888888888:key/90be6df2-db60-4237-ad9b-a49260XXXXX",
		"arn:aws:iam::888888888888:role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX",
		"arn:aws:sts::888888888888:assumed-role/panther-app-LogProcessor-XXXXXXXXXXXX-FunctionRole-XXXXXXXXXX/panther-log-processor",
		"arn:aws:lambda:us-east-1:888888888888:function:panther-log-processor")
	expectedEvent.AppendAnyAWSAccountIds("888888888888")
	expectedEvent.AppendAnyIPAddresses("1.2.3.4")

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
	for i, expectedEvent := range expectedEvents {
		event := events[i].Event().(*CloudTrail)
		testutil.EqualPantherLog(t, expectedEvent.Log(), event.Logs())
	}
}
