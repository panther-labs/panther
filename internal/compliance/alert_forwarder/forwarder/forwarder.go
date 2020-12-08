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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	alertApiModels "github.com/panther-labs/panther/internal/log_analysis/alerts_api/models"
	"github.com/panther-labs/panther/pkg/metrics"
)

const defaultTimePartition = "defaultPartition"

type Handler struct {
	SqsClient        sqsiface.SQSAPI
	DdbClient        dynamodbiface.DynamoDBAPI
	AlertTable       string
	AlertingQueueURL string
	MetricsLogger    metrics.Logger
}

func (h *Handler) Do(alert models.Alert) error {
	// Persist to DDB
	if err := h.storeNewAlert(alert); err != nil {
		return errors.Wrap(err, "failed to store new alert (policy) in DDB")
	}

	// Send to Dispatch queue
	if err := h.sendAlertNotification(alert); err != nil {
		return err
	}

	// Log stats
	if alert.Type == models.PolicyType {
		h.logStats(alert)
	}

	return nil
}

func (h *Handler) logStats(alert models.Alert) {
	h.MetricsLogger.Log(
		[]metrics.Dimension{
			{Name: "Severity", Value: alert.Severity},
			{Name: "AnalysisType", Value: "Policy"},
			{Name: "AnalysisID", Value: alert.AnalysisID},
		},
		metrics.Metric{
			Name:  "AlertsCreated",
			Value: 1,
			Unit:  metrics.UnitCount,
		},
	)
}

func (h *Handler) storeNewAlert(alert models.Alert) error {
	// Here we re-use the same field names for alerts that were
	// generated from rules.
	dynamoAlert := &alertApiModels.Alert{
		ID:            *alert.AlertID,
		TimePartition: defaultTimePartition,
		Severity:      aws.String(alert.Severity),
		Title:         alert.Title,
		AlertPolicy: alertApiModels.AlertPolicy{
			PolicyID:          alert.AnalysisID,
			PolicyDisplayName: aws.StringValue(alert.AnalysisName),
			PolicyVersion:     aws.StringValue(alert.Version),
			PolicySourceID:    alert.AnalysisSourceID,
			ResourceTypes:     alert.ResourceTypes,
			ResourceID:        alert.ResourceID,
		},
		// Reuse part of the struct that was intended for Rules
		AlertDedupEvent: alertApiModels.AlertDedupEvent{
			RuleID:       alert.AnalysisID, // Not used, but needed to meet the `ruleId-creationTime-index` constraint
			CreationTime: alert.CreatedAt,
			UpdateTime:   alert.CreatedAt,
			Type:         alert.Type,
		},
	}

	marshaledAlert, err := dynamodbattribute.MarshalMap(dynamoAlert)
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

func (h *Handler) sendAlertNotification(alert models.Alert) error {
	msgBody, err := jsoniter.MarshalToString(alert)
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
