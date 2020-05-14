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
	var props APIGatewayAlarmProperties
	if err := parseProperties(event.ResourceProperties, &props); err != nil {
		return "", nil, err
	}

	if props.LatencyThresholdMs == 0 {
		props.LatencyThresholdMs = 1000
	}

	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		return "custom:alarms:api:" + props.APIName, nil, putGatewayAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteMetricAlarms(event.PhysicalResourceID,
			gatewayErrorAlarm, gatewayLatencyAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putGatewayAlarmGroup(props APIGatewayAlarmProperties) error {
	input := cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"API Gateway %s is experiencing high integration latency. See: %s#%s",
			props.APIName, alarmRunbook, props.APIName)),
		AlarmName: aws.String(fmt.Sprintf("Panther-%s-%s", gatewayLatencyAlarm, props.APIName)),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("ApiName"), Value: &props.APIName},
		},
		MetricName: aws.String("IntegrationLatency"),
		Namespace:  aws.String("AWS/ApiGateway"),
		Threshold:  &props.LatencyThresholdMs,
		Unit:       aws.String(cloudwatch.StandardUnitMilliseconds),
	}
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"API Gateway %s is reporting 5XX internal errors. See: %s#%s",
		props.APIName, alarmRunbook, props.APIName))
	input.AlarmName = aws.String(fmt.Sprintf("Panther-%s-%s", gatewayErrorAlarm, props.APIName))
	input.MetricName = aws.String("5XXError")
	input.Threshold = aws.Float64(float64(props.ErrorThreshold))
	input.Unit = aws.String(cloudwatch.StandardUnitCount)
	return putMetricAlarm(input)
}
