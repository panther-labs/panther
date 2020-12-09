package forwarder

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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/events"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestComplianceEventWithoutChange(t *testing.T) {
	t.Parallel()
	lambda := &testutils.LambdaMock{}
	firehose := &testutils.FirehoseMock{}

	sh := StreamHandler{
		LambdaClient:   lambda,
		FirehoseClient: firehose,
		StreamName:     "stream-name",
	}

	record := events.DynamoDBEventRecord{
		AWSRegion:      "eu-west-1",
		EventSource:    "aws:dynamodb",
		EventName:      "MODIFY",
		EventID:        "a04e16d70e2520ff8a3569354b55b3f5",
		EventVersion:   "1.1",
		EventSourceArn: "arn:aws:dynamodb:eu-west-1:123456789012:table/panther-compliance/stream/2020-12-09T13:15:55.723",
		Change: events.DynamoDBStreamRecord{
			Keys: map[string]*dynamodb.AttributeValue{
				"resourceId": {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"policyId":   {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
			},
			NewImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("PASS")},
				"lastUpdated":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607707952")},
			},

			OldImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("PASS")},
				"lastUpdated":    {S: aws.String("2020-12-09T14:36:18.288334104Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607704578")},
			},
		},
	}

	assert.NoError(t, sh.Run(context.Background(), zap.L(), &events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{record}}))
}

func TestComplianceEventStatusChange(t *testing.T) {
	t.Parallel()
	lambda := &testutils.LambdaMock{}
	firehose := &testutils.FirehoseMock{}

	sh := StreamHandler{
		LambdaClient:   lambda,
		FirehoseClient: firehose,
		StreamName:     "stream-name",
	}

	record := events.DynamoDBEventRecord{
		AWSRegion:      "eu-west-1",
		EventSource:    "aws:dynamodb",
		EventName:      "MODIFY",
		EventID:        "a04e16d70e2520ff8a3569354b55b3f5",
		EventVersion:   "1.1",
		EventSourceArn: "arn:aws:dynamodb:eu-west-1:123456789012:table/panther-compliance/stream/2020-12-09T13:15:55.723",
		Change: events.DynamoDBStreamRecord{
			Keys: map[string]*dynamodb.AttributeValue{
				"resourceId": {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"policyId":   {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
			},
			NewImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("FAIL")},
				"lastUpdated":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607707952")},
			},

			OldImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("PASS")},
				"lastUpdated":    {S: aws.String("2020-12-09T14:36:18.288334104Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607704578")},
			},
		},
	}

	assert.NoError(t, sh.Run(context.Background(), zap.L(), &events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{record}}))
}

