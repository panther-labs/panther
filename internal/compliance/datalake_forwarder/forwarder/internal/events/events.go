package events

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
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// The DynamoDBEvent stream event handled to Lambda
// http://docs.aws.amazon.com/lambda/latest/dg/eventsources.html#eventsources-ddb-update
// THIS IS AN EXACT COPY OF "github.com/aws/aws-lambda-go/events#DynamoDBEvent"
// The difference lays in the 'DynamoDBStreamRecord' (see below)
type DynamoDBEvent struct {
	Records []DynamoDBEventRecord `json:"Records"`
}

type DynamoDBEventRecord struct {
	// The region in which the GetRecords request was received.
	AWSRegion string `json:"awsRegion"`

	// The main body of the stream record, containing all of the DynamoDB-specific
	// fields.
	Change DynamoDBStreamRecord `json:"dynamodb"`

	// A globally unique identifier for the event that was recorded in this stream
	// record.
	EventID string `json:"eventID"`

	// The type of data modification that was performed on the DynamoDB table:
	//
	//    * INSERT - a new item was added to the table.
	//
	//    * MODIFY - one or more of an existing item's attributes were modified.
	//
	//    * REMOVE - the item was deleted from the table
	EventName string `json:"eventName"`

	// The AWS service from which the stream record originated. For DynamoDB Streams,
	// this is aws:dynamodb.
	EventSource string `json:"eventSource"`

	// The version number of the stream record format. This number is updated whenever
	// the structure of Record is modified.
	//
	// Client applications must not assume that eventVersion will remain at a particular
	// value, as this number is subject to change at any time. In general, eventVersion
	// will only increase as the low-level DynamoDB Streams API evolves.
	EventVersion string `json:"eventVersion"`

	// The event source ARN of DynamoDB
	EventSourceArn string `json:"eventSourceARN"`

	// Items that are deleted by the Time to Live process after expiration have
	// the following fields:
	//
	//    * Records[].userIdentity.type
	//
	// "Service"
	//
	//    * Records[].userIdentity.principalId
	//
	// "dynamodb.amazonaws.com"
	UserIdentity *events.DynamoDBUserIdentity `json:"userIdentity,omitempty"`
}

// DynamoDBStreamRecord represents a description of a single data modification that was performed on an item
// in a DynamoDB table.
// THIS IS AN ALMOST EXACT COPY OF "github.com/aws/aws-lambda-go/events#DynamoDBStreamRecord"
// with the only difference being the values of 'Keys', 'NewImage', 'OldImage' fields
type DynamoDBStreamRecord struct {
	// The approximate date and time when the stream record was created, in UNIX
	// epoch time (http://www.epochconverter.com/) format.
	ApproximateCreationDateTime events.SecondsEpochTime `json:"ApproximateCreationDateTime,omitempty"`

	// The primary key attribute(s) for the DynamoDB item that was modified.
	Keys map[string]*dynamodb.AttributeValue `json:"Keys,omitempty"`

	// The item in the DynamoDB table as it appeared after it was modified.
	NewImage map[string]*dynamodb.AttributeValue `json:"NewImage,omitempty"`

	// The item in the DynamoDB table as it appeared before it was modified.
	OldImage map[string]*dynamodb.AttributeValue `json:"OldImage,omitempty"`

	// The sequence number of the stream record.
	SequenceNumber string `json:"SequenceNumber"`

	// The size of the stream record, in bytes.
	SizeBytes int64 `json:"SizeBytes"`

	// The type of data from the modified DynamoDB item that was captured in this
	// stream record.
	StreamViewType string `json:"StreamViewType"`
}
