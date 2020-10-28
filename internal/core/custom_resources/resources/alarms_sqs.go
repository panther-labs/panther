package resources

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
	"fmt"
	"time"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

const (
	sqsDeadLetterAlarm = "SQSDeadLetters"
	sqsAgeAlarm        = "SQSTooOld"
)

type SQSAlarmProperties struct {
	AlarmTopicArn       string   `validate:"required"`
	QueueName           string   `validate:"required"`
	IsDLQ               bool     `json:",string"`
	AgeThresholdSeconds *float64 `json:",string"` // if present, override default
}

func customSQSAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props SQSAlarmProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		return "custom:alarms:sqs:" + props.QueueName, nil, putSQSAlarmGroup(props)

	case cfn.RequestDelete:
		// Only of the two alarms will be defined, but we can just delete both - one will be ignored
		return event.PhysicalResourceID, nil, deleteAlarms(
			event.PhysicalResourceID, sqsAgeAlarm, sqsDeadLetterAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putSQSAlarmGroup(props SQSAlarmProperties) error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions:       []*string{&props.AlarmTopicArn},
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("QueueName"), Value: &props.QueueName},
		},
		EvaluationPeriods: aws.Int64(1),
		Namespace:         aws.String("AWS/SQS"),
		Period:            aws.Int64(300),
	}

	if props.IsDLQ {
		// Alarm for any messages in a dead-letter queue (DLQ)
		input.AlarmDescription = aws.String(fmt.Sprintf(
			"SQS queue %s has dead letters. See: %s#%s",
			props.QueueName, alarmRunbook, props.QueueName))
		input.AlarmName = aws.String(
			fmt.Sprintf("Panther-%s-%s", sqsDeadLetterAlarm, props.QueueName))
		input.MetricName = aws.String("ApproximateNumberOfMessagesVisible")
		input.Statistic = aws.String(cloudwatch.StatisticSum)
		input.Threshold = aws.Float64(0)
		input.Unit = aws.String(cloudwatch.StandardUnitCount)
	} else {
		// Alarm if messages are too old, which means they're not being processed
		input.AlarmDescription = aws.String(fmt.Sprintf(
			"SQS queue %s is not being processed fast enough. See: %s#%s",
			props.QueueName, alarmRunbook, props.QueueName))
		input.AlarmName = aws.String(
			fmt.Sprintf("Panther-%s-%s", sqsAgeAlarm, props.QueueName))
		input.MetricName = aws.String("ApproximateAgeOfOldestMessage")
		input.Statistic = aws.String(cloudwatch.StatisticMaximum)
		threshold := 15 * time.Minute.Seconds()
		if props.AgeThresholdSeconds != nil {
			threshold = *props.AgeThresholdSeconds
		}
		input.Threshold = &threshold
		input.Unit = aws.String(cloudwatch.StandardUnitSeconds)
		input.EvaluationPeriods = aws.Int64(3)
	}

	return putMetricAlarm(input)
}
