package forwarder

import (
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/pkg/errors"
)

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
var (
	alertsTable                           = os.Getenv("ALERTS_TABLE")
	awsSession                            = session.Must(session.NewSession())
	ddbClient   dynamodbiface.DynamoDBAPI = dynamodb.New(awsSession)
)

const defaultTimePartition = "defaultPartition"

func Process(event *AlertDedupEvent) error {
	alert := &Alert{
		ID:              generateAlertID(event),
		TimePartition:   defaultTimePartition,
		AlertDedupEvent: *event,
	}

	marshalledAlert, err := dynamodbattribute.MarshalMap(alert)
	if err != nil {
		return errors.Wrap(err, "failed to marshall alert")
	}
	putItemRequest := &dynamodb.PutItemInput{
		Item:      marshalledAlert,
		TableName: aws.String(alertsTable),
	}
	_, err = ddbClient.PutItem(putItemRequest)
	if err != nil {
		return errors.Wrap(err, "failed to update store alert")
	}
	return nil
}

func generateAlertID(event *AlertDedupEvent) string {
	return event.RuleID + ":" + event.DeduplicationString + ":" + strconv.FormatInt(event.AlertCount, 10)
}
