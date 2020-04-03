package forwarder

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
	"crypto/md5" // nolint(gosec)
	"encoding/hex"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	policiesoperations "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	alertModel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

const defaultTimePartition = "defaultPartition"

func HandleUpdatingAlertInfo(event *AlertDedupEvent) error {
	alert := &Alert{
		ID:              generateAlertID(event),
		TimePartition:   defaultTimePartition,
		AlertDedupEvent: *event,
	}

	marshaledAlert, err := dynamodbattribute.MarshalMap(alert)
	if err != nil {
		return errors.Wrap(err, "failed to marshal alert")
	}
	putItemRequest := &dynamodb.PutItemInput{
		Item:      marshaledAlert,
		TableName: aws.String(env.AlertsTable),
	}
	_, err = ddbClient.PutItem(putItemRequest)
	if err != nil {
		return errors.Wrap(err, "failed to update store alert")
	}
	return nil
}

func HandleSendingAlertNotification(oldAlertDedupEvent, newAlertDedupEvent *AlertDedupEvent) error {
	// If we already have processed a alert deduplication for a rule
	// and the alert count is the same, it means we haven't generated a new alert, thus we don't need to send a notification
	if oldAlertDedupEvent != nil && oldAlertDedupEvent.AlertCount == newAlertDedupEvent.AlertCount {
		return nil
	}

	alert, err := getAlert(newAlertDedupEvent)
	if err != nil {
		return errors.Wrap(err, "failed to get alert information")
	}
	if alert == nil {
		return nil
	}
	msgBody, err := jsoniter.MarshalToString(alert)
	if err != nil {
		return errors.Wrap(err, "failed to marshal alert notification")
	}

	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(env.AlertingQueueURL),
		MessageBody: aws.String(msgBody),
	}
	_, err = sqsClient.SendMessage(input)
	if err != nil {
		return errors.Wrap(err, "failed to send notification")
	}
	return nil
}

func generateAlertID(event *AlertDedupEvent) string {
	key := event.RuleID + ":" + strconv.FormatInt(event.AlertCount, 10) + ":" + event.DeduplicationString
	keyHash := md5.Sum([]byte(key)) // nolint(gosec)
	return hex.EncodeToString(keyHash[:])
}

func getAlert(alert *AlertDedupEvent) (*alertModel.Alert, error) {
	rule, err := policyClient.Operations.GetRule(&policiesoperations.GetRuleParams{
		RuleID:     alert.RuleID,
		VersionID:  aws.String(alert.RuleVersion),
		HTTPClient: httpClient,
	})

	if err != nil {
		// if rule was not found, return nil
		if _, ok := err.(*policiesoperations.GetRuleNotFound); ok {
			return nil, nil
		}

		return nil, errors.Wrapf(err, "failed to fetch information for ruleID %s", alert.RuleID)
	}

	return &alertModel.Alert{
		CreatedAt:         aws.Time(alert.CreationTime),
		PolicyDescription: aws.String(string(rule.Payload.Description)),
		PolicyID:          aws.String(alert.RuleID),
		PolicyVersionID:   aws.String(alert.RuleVersion),
		PolicyName:        aws.String(string(rule.Payload.DisplayName)),
		Runbook:           aws.String(string(rule.Payload.Runbook)),
		Severity:          aws.String(alert.Severity),
		Tags:              aws.StringSlice(rule.Payload.Tags),
		Type:              aws.String(alertModel.RuleType),
		AlertID:           aws.String(generateAlertID(alert)),
		Title:             alert.Title,
	}, nil
}
