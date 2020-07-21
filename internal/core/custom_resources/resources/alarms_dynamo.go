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
	dynamoUserErrorAlarm    = "DynamoDBUserErrors"
	dynamoSystemErrorAlarm  = "DynamoDBSystemErrors"
	dynamoLatencyErrorAlarm = "DynamoDBHighLatency"
	dynamoThrottleAlarm     = "DynamoDBThrottles"
)

type DynamoDBAlarmProperties struct {
	AlarmTopicArn string `validate:"required"`
	TableName     string `validate:"required"`
}

func customDynamoDBAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props DynamoDBAlarmProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		return "custom:alarms:dynamodb:" + props.TableName, nil, putDynamoAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteAlarms(event.PhysicalResourceID,
			dynamoUserErrorAlarm, dynamoSystemErrorAlarm, dynamoLatencyErrorAlarm,
			dynamoThrottleAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putDynamoAlarmGroup(props DynamoDBAlarmProperties) error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"DynamoDB table %s has user errors. See: %s#%s",
			props.TableName, alarmRunbook, props.TableName)),
		AlarmName: aws.String(
			fmt.Sprintf("Panther-%s-%s", dynamoUserErrorAlarm, props.TableName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("TableName"), Value: &props.TableName},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String("UserErrors"),
		Namespace:         aws.String("AWS/DynamoDB"),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Threshold:         aws.Float64(0),
		Unit:              aws.String(cloudwatch.StandardUnitCount),
	}
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"DynamoDB table %s has internal errors - contact AWS support. See: %s#%s",
		props.TableName, alarmRunbook, props.TableName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", dynamoSystemErrorAlarm, props.TableName))
	input.MetricName = aws.String("SystemErrors")
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"DynamoDB table %s is throttling requests. See: %s#%s",
		props.TableName, alarmRunbook, props.TableName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", dynamoThrottleAlarm, props.TableName))
	input.MetricName = aws.String("ThrottledRequests")
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"DynamoDB table %s is experiencing high latency. See: %s#%s",
		props.TableName, alarmRunbook, props.TableName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", dynamoLatencyErrorAlarm, props.TableName))
	input.MetricName = aws.String("SuccessfulRequestLatency")
	input.Statistic = aws.String(cloudwatch.StatisticMaximum)
	input.Threshold = aws.Float64(1000)
	input.Unit = aws.String(cloudwatch.StandardUnitMilliseconds)
	return putMetricAlarm(input)
}
