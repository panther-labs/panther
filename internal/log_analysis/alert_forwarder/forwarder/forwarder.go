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
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	alertModel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

const defaultTimePartition = "defaultPartition"

type Handler struct {
	SqsClient        sqsiface.SQSAPI
	Cache            *RuleCache
	DdbClient        dynamodbiface.DynamoDBAPI
	AlertTable       string
	AlertingQueueURL string
}

func (h *Handler) Do(oldAlertDedupEvent, newAlertDedupEvent *AlertDedupEvent) (err error) {
	var oldRule *models.Rule
	if oldAlertDedupEvent != nil {
		oldRule, err = h.Cache.Get(oldAlertDedupEvent.RuleID, oldAlertDedupEvent.RuleVersion)
		if err != nil {
			return errors.Wrap(err, "failed to get rule information")
		}
	}

	newRule, err := h.Cache.Get(newAlertDedupEvent.RuleID, newAlertDedupEvent.RuleVersion)
	if err != nil {
		return errors.Wrap(err, "failed to get rule information")
	}

	if shouldIgnoreChange(newRule, newAlertDedupEvent) {
		return nil
	}

	if needToCreateNewAlert(oldRule, oldAlertDedupEvent, newAlertDedupEvent) {
		return h.handleNewAlert(newRule, newAlertDedupEvent)
	}
	return h.updateExistingAlert(newAlertDedupEvent)
}

func shouldIgnoreChange(rule *models.Rule, alertDedupEvent *AlertDedupEvent) bool {
	// If the number of matched events hasn't crossed the threshold for the rule, don't create a new alert.
	return alertDedupEvent.EventCount < int64(rule.Threshold)
}

func needToCreateNewAlert(oldRule *models.Rule, oldAlertDedupEvent, newAlertDedupEvent *AlertDedupEvent) bool {
	if oldAlertDedupEvent == nil {
		// If this is the first time we see an alert deduplication entry, create an alert
		return true
	}
	if oldAlertDedupEvent.AlertCount != newAlertDedupEvent.AlertCount {
		// If this is an alert deduplication entry for a new alert, create the new alert
		return true
	}
	if oldAlertDedupEvent.EventCount < int64(oldRule.Threshold) {
		// If the previous alert dedup information was not above rule threshold, we need to create a new alert
		return true
	}
	return false
}

func (h *Handler) handleNewAlert(rule *models.Rule, event *AlertDedupEvent) error {
	if err := h.storeNewAlert(rule, event); err != nil {
		return errors.Wrap(err, "failed to store new alert in DDB")
	}
	return h.sendAlertNotification(rule, event)
}

func (h *Handler) updateExistingAlert(event *AlertDedupEvent) error {
	// When updating alert, we need to update only 3 fields
	// - The number of events included in the alert
	// - The log types of the events in the alert
	// - The alert update time
	updateExpression := expression.
		Set(expression.Name(alertTableEventCountAttribute), expression.Value(event.EventCount)).
		Set(expression.Name(alertTableLogTypesAttribute), expression.Value(event.LogTypes)).
		Set(expression.Name(alertTableUpdateTimeAttribute), expression.Value(event.UpdateTime))
	expr, err := expression.NewBuilder().WithUpdate(updateExpression).Build()
	if err != nil {
		return errors.Wrap(err, "failed to build update expression")
	}

	updateInput := &dynamodb.UpdateItemInput{
		TableName:                 &h.AlertTable,
		UpdateExpression:          expr.Update(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key: map[string]*dynamodb.AttributeValue{
			alertTablePartitionKey: {S: aws.String(generateAlertID(event))},
		},
	}

	_, err = h.DdbClient.UpdateItem(updateInput)
	if err != nil {
		return errors.Wrap(err, "failed to update alert")
	}
	return nil
}

func (h *Handler) storeNewAlert(rule *models.Rule, alertDedup *AlertDedupEvent) error {
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
		TableName: &h.AlertTable,
	}
	_, err = h.DdbClient.PutItem(putItemRequest)
	if err != nil {
		return errors.Wrap(err, "failed to update store alert")
	}
	return nil
}

func (h *Handler) sendAlertNotification(rule *models.Rule, alertDedup *AlertDedupEvent) error {
	alertNotification := &alertModel.Alert{
		AlertID:             aws.String(generateAlertID(alertDedup)),
		AnalysisDescription: aws.String(string(rule.Description)),
		AnalysisID:          alertDedup.RuleID,
		CreatedAt:           alertDedup.CreationTime,
		OutputIds:           rule.OutputIds,
		AnalysisName:        getRuleDisplayName(rule),
		Runbook:             aws.String(string(rule.Runbook)),
		Severity:            string(rule.Severity),
		Tags:                rule.Tags,
		Type:                alertModel.RuleType,
		Title:               aws.String(getAlertTitle(rule, alertDedup)),
		Version:             &alertDedup.RuleVersion,
	}

	msgBody, err := jsoniter.MarshalToString(alertNotification)
	if err != nil {
		return errors.Wrap(err, "failed to marshal alert notification")
	}

	input := &sqs.SendMessageInput{
		QueueUrl:    &h.AlertingQueueURL,
		MessageBody: &msgBody,
	}
	_, err = h.SqsClient.SendMessage(input)
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
