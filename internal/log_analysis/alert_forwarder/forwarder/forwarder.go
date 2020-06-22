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
	"crypto/md5" // nolint(gosec)
	"encoding/hex"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
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
	return updateExistingAlert(newAlertDedupEvent)
}

func needToCreateNewAlert(oldAlertDedupEvent, newAlertDedupEvent *AlertDedupEvent) bool {
	return oldAlertDedupEvent == nil || oldAlertDedupEvent.AlertCount != newAlertDedupEvent.AlertCount
}

func handleNewAlert(event *AlertDedupEvent) error {
	ruleInfo, err := getRuleInfo(event)
	if err != nil {
		return errors.Wrap(err, "failed to get rule information")
	}

	if err := storeNewAlert(ruleInfo, event); err != nil {
		return errors.Wrap(err, "failed to store new alert in DDB")
	}
	return sendAlertNotification(ruleInfo, event)
}

func updateExistingAlert(event *AlertDedupEvent) error {
	// When updating alert, we need to update only 3 fields
	// - The number of events included in the alert
	// - The log types of the events in the alert
	// - The alert update time
	updateExpression := expression.
		Set(expression.Name(alertTableEventCountAttribute), expression.Value(aws.Int64(event.EventCount))).
		Set(expression.Name(alertTableLogTypesAttribute), expression.Value(aws.StringSlice(event.LogTypes))).
		Set(expression.Name(alertTableUpdateTimeAttribute), expression.Value(aws.Time(event.UpdateTime)))
	expr, err := expression.NewBuilder().WithUpdate(updateExpression).Build()
	if err != nil {
		return errors.Wrap(err, "failed to build update expression")
	}

	updateInput := &dynamodb.UpdateItemInput{
		TableName:                 aws.String(env.AlertsTable),
		UpdateExpression:          expr.Update(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key: map[string]*dynamodb.AttributeValue{
			alertTablePartitionKey: {S: aws.String(generateAlertID(event))},
		},
	}

	_, err = ddbClient.UpdateItem(updateInput)
	if err != nil {
		return errors.Wrap(err, "failed to update alert")
	}
	return nil
}

func storeNewAlert(rule *models.Rule, alertDedup *AlertDedupEvent) error {
	alert := &Alert{
		ID:              generateAlertID(alertDedup),
		TimePartition:   defaultTimePartition,
		Severity:        string(rule.Severity),
		RuleDisplayName: getRuleDisplayName(rule),
		Title:           getAlertTitle(rule, alertDedup),
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
		CreatedAt:           alertDedup.CreationTime,
		AnalysisDescription: aws.String(string(rule.Description)),
		AnalysisID:          alertDedup.RuleID,
		Version:             aws.String(alertDedup.RuleVersion),
		AnalysisName:        getRuleDisplayName(rule),
		Runbook:             aws.String(string(rule.Runbook)),
		Severity:            string(rule.Severity),
		Tags:                rule.Tags,
		Type:                alertModel.RuleType,
		AlertID:             aws.String(generateAlertID(alertDedup)),
		Title:               aws.String(getAlertTitle(rule, alertDedup)),
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
	ruleDisplayName := getRuleDisplayName(rule)
	if ruleDisplayName != nil {
		return *ruleDisplayName
	}
	return string(rule.ID)
}

func getRuleDisplayName(rule *models.Rule) *string {
	if len(rule.DisplayName) > 0 {
		return aws.String(string(rule.DisplayName))
	}
	return nil
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
