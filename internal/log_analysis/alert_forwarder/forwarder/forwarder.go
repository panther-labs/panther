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
	"go.uber.org/zap"

	ruleModel "github.com/panther-labs/panther/api/lambda/analysis/models"
	alertModel "github.com/panther-labs/panther/api/lambda/delivery/models"
	alertApiModels "github.com/panther-labs/panther/internal/log_analysis/alerts_api/models"
	"github.com/panther-labs/panther/pkg/metrics"
)

const defaultTimePartition = "defaultPartition"

var skipOutput = []string{"SKIP"}

type Handler struct {
	SqsClient        sqsiface.SQSAPI
	Cache            RuleCache
	DdbClient        dynamodbiface.DynamoDBAPI
	AlertTable       string
	AlertingQueueURL string
	MetricsLogger    metrics.Logger
}

func (h *Handler) Do(oldAlertDedupEvent, newAlertDedupEvent *alertApiModels.AlertDedupEvent) (err error) {
	var oldRule *ruleModel.Rule
	if oldAlertDedupEvent != nil {
		oldRule, err = h.Cache.Get(oldAlertDedupEvent.RuleID, oldAlertDedupEvent.RuleVersion)
		if err != nil {
			return errors.Wrapf(err, "failed to get rule information for %s.%s", oldAlertDedupEvent.RuleID, oldAlertDedupEvent.RuleVersion)
		}
	}

	newRule, err := h.Cache.Get(newAlertDedupEvent.RuleID, newAlertDedupEvent.RuleVersion)
	if err != nil {
		return errors.Wrapf(err, "failed to get rule information for %s.%s", newAlertDedupEvent.RuleID, newAlertDedupEvent.RuleVersion)
	}

	if shouldIgnoreChange(newRule, newAlertDedupEvent) {
		return nil
	}
	if needToCreateNewAlert(oldRule, oldAlertDedupEvent, newAlertDedupEvent) {
		return h.handleNewAlert(newRule, newAlertDedupEvent)
	}
	return h.updateExistingAlert(newAlertDedupEvent)
}

func shouldIgnoreChange(rule *ruleModel.Rule, alertDedupEvent *alertApiModels.AlertDedupEvent) bool {
	// If the number of matched events hasn't crossed the threshold for the rule, don't create a new alert.
	return alertDedupEvent.Type == alertModel.RuleType && alertDedupEvent.EventCount < int64(rule.Threshold)
}

func needToCreateNewAlert(oldRule *ruleModel.Rule, oldAlertDedupEvent, newAlertDedupEvent *alertApiModels.AlertDedupEvent) bool {
	if oldAlertDedupEvent == nil {
		// If this is the first time we see an alert deduplication entry, create an alert
		return true
	}
	if oldAlertDedupEvent.AlertCount != newAlertDedupEvent.AlertCount {
		// If this is an alert deduplication entry for a new alert, create the new alert
		return true
	}
	if shouldIgnoreChange(oldRule, oldAlertDedupEvent) {
		// if the previous notification was ignored, we need to send a notification
		return true
	}
	return false
}

func (h *Handler) handleNewAlert(rule *ruleModel.Rule, event *alertApiModels.AlertDedupEvent) error {
	if err := h.storeNewAlert(rule, event); err != nil {
		return errors.Wrap(err, "failed to store new alert in DDB")
	}

	err := h.sendAlertNotification(rule, event)
	if err == nil && event.Type == alertModel.RuleType {
		h.logStats(rule, event)
	}
	return err
}

func (h *Handler) logStats(rule *ruleModel.Rule, event *alertApiModels.AlertDedupEvent) {
	h.MetricsLogger.Log(
		[]metrics.Dimension{
			{Name: "Severity", Value: getSeverity(rule, event)},
			{Name: "AnalysisType", Value: "Rule"},
			{Name: "AnalysisID", Value: rule.ID},
		},
		metrics.Metric{
			Name:  "AlertsCreated",
			Value: 1,
			Unit:  metrics.UnitCount,
		},
	)
}

func (h *Handler) updateExistingAlert(event *alertApiModels.AlertDedupEvent) error {
	// When updating alert, we need to update only 3 fields
	// - The number of events included in the alert
	// - The log types of the events in the alert
	// - The alert update time
	updateExpression := expression.
		Set(expression.Name(alertApiModels.AlertTableEventCountAttribute), expression.Value(event.EventCount)).
		Set(expression.Name(alertApiModels.AlertTableLogTypesAttribute), expression.Value(event.LogTypes)).
		Set(expression.Name(alertApiModels.AlertTableUpdateTimeAttribute), expression.Value(event.UpdateTime))
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
			alertApiModels.AlertTablePartitionKey: {S: aws.String(generateAlertID(event))},
		},
	}

	_, err = h.DdbClient.UpdateItem(updateInput)
	if err != nil {
		return errors.Wrap(err, "failed to update alert")
	}
	return nil
}

func (h *Handler) storeNewAlert(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) error {
	alert := &alertApiModels.Alert{
		ID:                  generateAlertID(alertDedup),
		TimePartition:       defaultTimePartition,
		Severity:            aws.String(getSeverity(rule, alertDedup)),
		RuleDisplayName:     getRuleDisplayName(rule),
		Title:               getTitle(rule, alertDedup),
		FirstEventMatchTime: alertDedup.CreationTime,
		LogTypes:            alertDedup.LogTypes,
		AlertDedupEvent: alertApiModels.AlertDedupEvent{
			RuleID:              alertDedup.RuleID,
			RuleVersion:         alertDedup.RuleVersion,
			DeduplicationString: alertDedup.DeduplicationString,
			// In case a rule has a threshold, we want the alert creation time to be the same time
			// as the update time -> the time that an update(new event) caused the matched events to exceed threshold
			// In case the rule doesnt' have a threshold, the two are anyway the same
			CreationTime: alertDedup.UpdateTime,
			UpdateTime:   alertDedup.UpdateTime,
			EventCount:   alertDedup.EventCount,
			LogTypes:     alertDedup.LogTypes,
			Type:         alertDedup.Type,
			// Generated Fields
			GeneratedTitle:        aws.String(getTitle(rule, alertDedup)),
			GeneratedDescription:  aws.String(getDescription(rule, alertDedup)),
			GeneratedReference:    aws.String(getReference(rule, alertDedup)),
			GeneratedRunbook:      aws.String(getRunbook(rule, alertDedup)),
			GeneratedDestinations: alertDedup.GeneratedDestinations,
		},
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
		return errors.Wrap(err, "failed to store alert")
	}

	return nil
}

func (h *Handler) sendAlertNotification(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) error {
	alertNotification := &alertModel.Alert{
		AlertID:      aws.String(generateAlertID(alertDedup)),
		AnalysisID:   alertDedup.RuleID,
		AnalysisName: getRuleDisplayName(rule),
		// In case a rule has a threshold, we want the alert creation time to be the same time
		// as the update time -> the time that an update(new event) caused the matched events to exceed threshold
		// In case the rule doesnt' have a threshold, the two are anyway the same
		CreatedAt: alertDedup.UpdateTime,
		OutputIds: getOutputIds(rule, alertDedup),
		Tags:      rule.Tags,
		Type:      alertDedup.Type,
		Version:   &alertDedup.RuleVersion,
		// Generated Fields
		AnalysisDescription: getDescription(rule, alertDedup),
		Reference:           getReference(rule, alertDedup),
		Runbook:             getRunbook(rule, alertDedup),
		Severity:            getSeverity(rule, alertDedup),
		Title:               getTitle(rule, alertDedup),
		Destinations:        getDestinations(alertDedup),
	}

	if alertDedup.AlertContext != nil {
		var context map[string]interface{}
		err := jsoniter.UnmarshalFromString(*alertDedup.AlertContext, &context)
		if err != nil {
			// best effort
			zap.L().Warn("failed to unmarshal alert context", zap.Error(err))
		} else {
			alertNotification.Context = context
		}
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

func getTitle(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) string {
	if alertDedup.GeneratedTitle != nil {
		return *alertDedup.GeneratedTitle
	}
	ruleDisplayName := getRuleDisplayName(rule)
	if ruleDisplayName != nil {
		return *ruleDisplayName
	}
	return rule.ID
}

func getDescription(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) string {
	if alertDedup.GeneratedDescription != nil {
		return *alertDedup.GeneratedDescription
	}
	return rule.Description
}

func getReference(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) string {
	if alertDedup.GeneratedReference != nil {
		return *alertDedup.GeneratedReference
	}
	return rule.Reference
}

func getRunbook(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) string {
	if alertDedup.GeneratedRunbook != nil {
		return *alertDedup.GeneratedRunbook
	}
	return rule.Runbook
}

func getSeverity(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) string {
	if alertDedup.GeneratedSeverity != nil {
		return *alertDedup.GeneratedSeverity
	}
	return string(rule.Severity)
}

func getOutputIds(rule *ruleModel.Rule, alertDedup *alertApiModels.AlertDedupEvent) []string {
	if alertDedup.GeneratedDestinations != nil {
		if len(alertDedup.GeneratedDestinations) == 0 {
			return skipOutput
		}
		return alertDedup.GeneratedDestinations
	}
	return rule.OutputIDs
}

func getDestinations(alertDedup *alertApiModels.AlertDedupEvent) []string {
	if alertDedup.GeneratedDestinations != nil && len(alertDedup.GeneratedDestinations) == 0 {
		return skipOutput
	}
	return alertDedup.GeneratedDestinations
}

func getRuleDisplayName(rule *ruleModel.Rule) *string {
	if len(rule.DisplayName) > 0 {
		return &rule.DisplayName
	}
	return nil
}

func generateAlertID(event *alertApiModels.AlertDedupEvent) string {
	key := event.RuleID + ":" + strconv.FormatInt(event.AlertCount, 10) + ":" + event.DeduplicationString
	keyHash := md5.Sum([]byte(key)) // nolint(gosec)
	return hex.EncodeToString(keyHash[:])
}
