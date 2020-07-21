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

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

const (
	snsFailedNotificationsAlarm = "SNSNotificationsFailed"
)

type SNSAlarmProperties struct {
	AlarmTopicArn string `validate:"required"`
	TopicName     string `validate:"required"`
}

func customSNSAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props SNSAlarmProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		return "custom:alarms:sns:" + props.TopicName, nil, putSNSAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteAlarms(
			event.PhysicalResourceID, snsFailedNotificationsAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putSNSAlarmGroup(props SNSAlarmProperties) error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"SNS topic %s is failing. See: %s#%s",
			props.TopicName, alarmRunbook, props.TopicName)),
		AlarmName: aws.String(
			fmt.Sprintf("Panther-%s-%s", snsFailedNotificationsAlarm, props.TopicName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("TopicName"), Value: &props.TopicName},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String("NumberOfNotificationsFailed"),
		Namespace:         aws.String("AWS/SNS"),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Threshold:         aws.Float64(0),
		Unit:              aws.String(cloudwatch.StandardUnitCount),
	}
	return putMetricAlarm(input)
}
