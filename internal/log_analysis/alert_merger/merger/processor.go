package merger

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
	"crypto/sha1" // nolint: gosec
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	policiesclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	policiesoperations "github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	alertModel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	tableModel "github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	recentAlertsTable = aws.String(os.Getenv("RECENT_ALERTS_TABLE"))
	eventsTable       = aws.String(os.Getenv("EVENTS_TABLE"))
	alertsTable       = aws.String(os.Getenv("ALERTS_TABLE"))
	analysisAPIHost   = os.Getenv("ANALYSIS_API_HOST")
	analysisAPIPath   = os.Getenv("ANALYSIS_API_PATH")
	alertingQueueURL  = os.Getenv("ALERTING_QUEUE_URL")

	awsSession                           = session.Must(session.NewSession())
	ddbClient  dynamodbiface.DynamoDBAPI = dynamodb.New(awsSession)
	sqsClient  sqsiface.SQSAPI           = sqs.New(awsSession)

	httpClient   = gatewayapi.GatewayClient(awsSession)
	policyConfig = policiesclient.DefaultTransportConfig().
			WithHost(analysisAPIHost).
			WithBasePath(analysisAPIPath)
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
)

const eventMergingPeriodSeconds = 3600 // One hour

// Handle handles alert notifications
func Handle(notification *AlertNotification) error {
	event, err := storeMatchedEvent(notification)
	if err != nil {
		return errors.Wrap(err, "failed to store event")
	}

	isNewAlert, alertID, creationTime, err := getAlertInfo(notification)
	if err != nil {
		return errors.Wrap(err, "failed to get alert info")
	}

	if err = addEventToAlert(event, notification, alertID, creationTime); err != nil {
		return errors.Wrap(err, "failed to add event to alert")
	}

	if isNewAlert {
		if err = sendAlert(notification, alertID); err != nil {
			return errors.Wrap(err, "failed to send alert")
		}
	}

	return nil
}

func storeMatchedEvent(notification *AlertNotification) (*MatchedEvent, error) {
	event := &MatchedEvent{
		EventHash: sha1.Sum([]byte(*notification.Event)), //nolint: gosec
		Timestamp: notification.Timestamp,
		Event:     notification.Event,
	}

	marshalledItem, err := dynamodbattribute.MarshalMap(event)
	if err != nil {
		err = errors.WithStack(err)
		return nil, err
	}

	input := &dynamodb.PutItemInput{
		Item:      marshalledItem,
		TableName: eventsTable,
	}

	_, err = ddbClient.PutItem(input)
	if err != nil {
		err = errors.WithStack(err)
		return nil, err
	}
	return event, nil
}

// getAlertInfo returns whether a new alert is created, the alert key and the alert creation time
func getAlertInfo(notification *AlertNotification) (bool, *string, *time.Time, error) {
	timeNow := time.Now().Unix()
	expiresAt := int64(eventMergingPeriodSeconds) + timeNow

	updateExpression := expression.
		Set(expression.Name("creationTime"), expression.Value(aws.Int64(timeNow))).
		Set(expression.Name("expiresAt"), expression.Value(expiresAt)).
		Add(expression.Name("alertCount"), expression.Value(1))

	// The Condition will succeed only if `alertSuppressPeriod` has passed since the time the previous
	// alert was triggered
	conditionExpression := expression.Name("creationTime").LessThan(expression.Value(timeNow - int64(eventMergingPeriodSeconds))).
		Or(expression.Name("creationTime").AttributeNotExists())

	buildExpression, err := expression.NewBuilder().
		WithUpdate(updateExpression).
		WithCondition(conditionExpression).
		Build()
	if err != nil {
		err = errors.WithStack(err)
		return false, nil, nil, err
	}

	input := &dynamodb.UpdateItemInput{
		TableName: recentAlertsTable,
		Key: map[string]*dynamodb.AttributeValue{
			"ruleId": {S: notification.RuleID},
		},
		UpdateExpression:          buildExpression.Update(),
		ConditionExpression:       buildExpression.Condition(),
		ExpressionAttributeNames:  buildExpression.Names(),
		ExpressionAttributeValues: buildExpression.Values(),
		ReturnValues:              aws.String(dynamodb.ReturnValueAllNew),
	}

	response, err := ddbClient.UpdateItem(input)
	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			zap.L().Debug("update on ddb failed on condition, we will not trigger an alert")
			alertID, alertCreationTime, err := getCurrentAlertInfo(notification)
			return false, alertID, alertCreationTime, err
		}
		err = errors.WithStack(err)
		return false, nil, nil, err
	}

	compositeAlertKey := compositeAlertID(notification.RuleID, response.Attributes["alertCount"].N)
	alertCreationTime, err := stringToTime(response.Attributes["creationTime"].N)
	if err != nil {
		err = errors.WithStack(err)
		return false, nil, nil, err
	}

	return true, compositeAlertKey, alertCreationTime, nil
}

func getCurrentAlertInfo(notification *AlertNotification) (*string, *time.Time, error) {
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"ruleId": {S: notification.RuleID},
		},
		TableName: recentAlertsTable,
	}

	response, err := ddbClient.GetItem(input)
	if err != nil {
		err = errors.WithStack(err)
		return nil, nil, err
	}

	alertID := compositeAlertID(notification.RuleID, response.Item["alertCount"].N)
	alertCreationTime, err := stringToTime(response.Item["creationTime"].N)
	if err != nil {
		err = errors.WithStack(err)
		return nil, nil, err
	}

	return alertID, alertCreationTime, nil
}

func stringToTime(input *string) (*time.Time, error) {
	unixTime, err := strconv.ParseInt(aws.StringValue(input), 10, 64)
	if err != nil {
		err = errors.WithStack(err)
		return nil, err
	}
	return aws.Time(time.Unix(unixTime, 0)), nil
}

func compositeAlertID(ruleID *string, alertCount *string) *string {
	return aws.String(*ruleID + "-" + *alertCount)
}

type eventHashSet [][sha1.Size]byte

// Marshal binary slice as a Dynamo BinarySet instead of a List
func (s eventHashSet) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	av.BS = make([][]byte, 0, len(s))
	for _, eventHash := range s {
		av.BS = append(av.BS, eventHash[:])
	}
	return nil
}

func addEventToAlert(event *MatchedEvent, alertNotification *AlertNotification, alertID *string, creationTime *time.Time) error {
	update := expression.
		Add(expression.Name("eventHashes"), expression.Value(eventHashSet([][sha1.Size]byte{event.EventHash}))).
		Set(expression.Name("creationTime"), expression.Value(creationTime)).
		Set(expression.Name("ruleId"), expression.Value(alertNotification.RuleID)).
		Set(expression.Name("lastEventMatched"), expression.Value(event.Timestamp)).
		Set(expression.Name(tableModel.TimePartitionKey), expression.Value(tableModel.TimePartitionKey))

	expr, err := expression.NewBuilder().WithUpdate(update).Build()
	if err != nil {
		err = errors.WithStack(err)
		return err
	}

	input := &dynamodb.UpdateItemInput{
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key: map[string]*dynamodb.AttributeValue{
			tableModel.AlertIDKey: {S: alertID},
		},
		TableName:        alertsTable,
		UpdateExpression: expr.Update(),
	}

	_, err = ddbClient.UpdateItem(input)
	if err != nil {
		err = errors.WithStack(err)
		return err
	}
	return nil
}

func sendAlert(notification *AlertNotification, alertID *string) error {
	alert, err := getAlert(notification, alertID)
	if err != nil {
		err = errors.WithStack(err)
		return err
	}
	msgBody, err := jsoniter.MarshalToString(alert)
	if err != nil {
		err = errors.WithStack(err)
		return err
	}

	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(alertingQueueURL),
		MessageBody: aws.String(msgBody),
	}
	_, err = sqsClient.SendMessage(input)
	if err != nil {
		err = errors.WithStack(err)
		return err
	}
	return nil
}

func getAlert(notification *AlertNotification, alertID *string) (*alertModel.Alert, error) {
	rule, err := policyClient.Operations.GetRule(&policiesoperations.GetRuleParams{
		RuleID:     *notification.RuleID,
		HTTPClient: httpClient,
	})

	if err != nil {
		err = errors.WithStack(err)
		return nil, err
	}

	return &alertModel.Alert{
		CreatedAt:         notification.Timestamp,
		PolicyDescription: aws.String(string(rule.Payload.Description)),
		PolicyID:          notification.RuleID,
		PolicyName:        aws.String(string(rule.Payload.DisplayName)),
		PolicyVersionID:   notification.RuleVersionID,
		Runbook:           aws.String(string(rule.Payload.Runbook)),
		Severity:          aws.String(string(rule.Payload.Severity)),
		Tags:              aws.StringSlice(rule.Payload.Tags),
		Type:              aws.String(alertModel.RuleType),
		AlertID:           alertID,
	}, nil
}
