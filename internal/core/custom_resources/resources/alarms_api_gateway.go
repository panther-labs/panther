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
	gatewayLatencyAlarm = "ApiGatewayHighIntegrationLatency"
	gatewayErrorAlarm   = "ApiGatewayServerErrors"
)

type APIGatewayAlarmProperties struct {
	APIName            string  `json:"ApiName" validate:"required"`
	AlarmTopicArn      string  `validate:"required"`
	ErrorThreshold     int     `json:",string" validate:"omitempty,min=0"`
	LatencyThresholdMs float64 `json:",string" validate:"omitempty,min=1"`
}

func customAPIGatewayAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props APIGatewayAlarmProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		if props.LatencyThresholdMs == 0 {
			props.LatencyThresholdMs = 1000
		}

		return "custom:alarms:api:" + props.APIName, nil, putGatewayAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteAlarms(event.PhysicalResourceID,
			gatewayErrorAlarm, gatewayLatencyAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putGatewayAlarmGroup(props APIGatewayAlarmProperties) error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"API Gateway %s is experiencing high integration latency. See: %s#%s",
			props.APIName, alarmRunbook, props.APIName)),
		AlarmName:          aws.String(fmt.Sprintf("Panther-%s-%s", gatewayLatencyAlarm, props.APIName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("ApiName"), Value: &props.APIName},
		},
		EvaluationPeriods: aws.Int64(3),
		MetricName:        aws.String("IntegrationLatency"),
		Namespace:         aws.String("AWS/ApiGateway"),
		Period:            aws.Int64(60),
		Statistic:         aws.String(cloudwatch.StatisticMaximum),
		Threshold:         &props.LatencyThresholdMs,
		Unit:              aws.String(cloudwatch.StandardUnitMilliseconds),
	}
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	// 5XX errors can be triggered by GatewayAPI internal errors or Lambda execution errors.
	// We don't have a way to differentiate between the two through Gateway API metrics. However, we have already
	// alarms on AWS Lambda invocation failures that would capture errors caused by Lambda failures.
	input.AlarmDescription = aws.String(fmt.Sprintf(
		"API Gateway %s is reporting 5XX internal errors from its lambda handler. See: %s#%s",
		props.APIName, alarmRunbook, props.APIName))
	input.AlarmName = aws.String(fmt.Sprintf("Panther-%s-%s", gatewayErrorAlarm, props.APIName))
	input.EvaluationPeriods = aws.Int64(3)
	input.MetricName = aws.String("5XXError")
	input.Period = aws.Int64(300)
	input.Statistic = aws.String(cloudwatch.StatisticSum)
	input.Threshold = aws.Float64(float64(props.ErrorThreshold))
	input.Unit = aws.String(cloudwatch.StandardUnitCount)
	return putMetricAlarm(input)
}
