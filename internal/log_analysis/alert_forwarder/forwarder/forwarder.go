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
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	alertModel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

const defaultTimePartition = "defaultPartition"

func Handle(oldAlertDedupEvent, newAlertDedupEvent *AlertDedupEvent) error {
	if needToCreateNewAlert(oldAlertDedupEvent, newAlertDedupEvent) {
		return handleNewAlert(newAlertDedupEvent)
	}
	return updateExistingAlertDetails(newAlertDedupEvent)
}

func needToCreateNewAlert(oldAlertDedupEvent, newAlertDedupEvent *AlertDedupEvent) bool {
	return oldAlertDedupEvent == nil || oldAlertDedupEvent.AlertCount != newAlertDedupEvent.AlertCount
}

func handleNewAlert(event *AlertDedupEvent) error {
	ruleInfo, err := getRuleInfo(event)
	if err != nil {
		return err
	}

	if err := storeNewAlert(ruleInfo, event); err != nil {
		return errors.Wrap(err, "failed to store new alert in DDB")
	}
	return sendAlertNotification(ruleInfo, event)
}

func updateExistingAlertDetails(event *AlertDedupEvent) error {
	updateInput := dynamodb.UpdateItemInput{

	}
}

func storeNewAlert(rule *models.Rule, alertDedup *AlertDedupEvent) error {
	alert := &Alert{
		ID:              generateAlertID(alertDedup),
		TimePartition:   defaultTimePartition,
		Severity:        string(rule.Severity),
		Title: getAlertTitle(rule, alertDedup),
		AlertDedupEvent: *alertDedup,
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

func sendAlertNotification(rule *models.Rule, alertDedup *AlertDedupEvent) error {
	alertNotification := &alertModel.Alert{
		CreatedAt:         aws.Time(alertDedup.CreationTime),
		PolicyDescription: aws.String(string(rule.Description)),
		PolicyID:          aws.String(alertDedup.RuleID),
		PolicyVersionID:   aws.String(alertDedup.RuleVersion),
		PolicyName:        aws.String(string(rule.DisplayName)),
		Runbook:           aws.String(string(rule.Runbook)),
		Severity:          aws.String(string(rule.Severity)),
		Tags:              aws.StringSlice(rule.Tags),
		Type:              aws.String(alertModel.RuleType),
		AlertID:           aws.String(generateAlertID(alertDedup)),
		Title:             aws.String(getAlertTitle(rule, alertDedup)),
	}

	msgBody, err := jsoniter.MarshalToString(alertNotification)
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

func getAlertTitle(rule *models.Rule, alertDedup *AlertDedupEvent) string {
	if alertDedup.GeneratedTitle != nil {
		return *alertDedup.GeneratedTitle
	}

	if len(rule.DisplayName) > 0 {
		return string(rule.DisplayName) + " failed"
	}
	return string(rule.ID) + " failed"
}

func generateAlertID(event *AlertDedupEvent) string {
	key := event.RuleID + ":" + strconv.FormatInt(event.AlertCount, 10) + ":" + event.DeduplicationString
	keyHash := md5.Sum([]byte(key)) // nolint(gosec)
	return hex.EncodeToString(keyHash[:])
}

func getRuleInfo(event *AlertDedupEvent) (*models.Rule, error) {
	rule, err := policyClient.Operations.GetRule(&policiesoperations.GetRuleParams{
		RuleID:     event.RuleID,
		VersionID:  aws.String(event.RuleVersion),
		HTTPClient: httpClient,
	})

	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch information for ruleID [%s], version [%s]",
			event.RuleID, event.RuleVersion)
	}
	return rule.Payload, nil
}
