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
	"go.uber.org/zap"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

const (
	alarmRunbook = "https://docs.runpanther.io/operations/runbooks"

	gatewayLatencyAlarm = "ApiGatewayHighIntegrationLatency"
	gatewayErrorAlarm   = "ApiGatewayServerErrors"
)

type ApiGatewayAlarmProperties struct {
	ApiName            string  `validate:"required"`
	AlarmTopicArn      string  `validate:"required"`
	ErrorThreshold     int     `validate:"omitempty,min=0"`
	LatencyThresholdMs float64 `validate:"omitempty,min=100"`
}

// Add metric filters to a Lambda function's CloudWatch log group
func customAlarmsApiGateway(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	var props ApiGatewayAlarmProperties
	if err := parseProperties(event.ResourceProperties, &props); err != nil {
		return "", nil, err
	}

	if props.LatencyThresholdMs == 0 {
		props.LatencyThresholdMs = 1000
	}

	switch event.RequestType {
	case cfn.RequestCreate:
		return "custom:alarms:api:" + props.ApiName, nil, putGatewayAlarmGroup(props)

	case cfn.RequestUpdate:
		// TODO
		return event.PhysicalResourceID, nil, nil

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteGatewayAlarmGroup(event.PhysicalResourceID)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putGatewayAlarmGroup(props ApiGatewayAlarmProperties) error {
	client := getCloudWatchClient()
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"API Gateway %s is experiencing high integration latency. See: %s#%s",
			props.ApiName, alarmRunbook, props.ApiName)),
		AlarmName: aws.String(fmt.Sprintf("Panther-%s-%s", gatewayLatencyAlarm, props.ApiName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("Name"), Value: &props.ApiName},
		},
		EvaluationPeriods: aws.Int64(5),
		MetricName:        aws.String("IntegrationLatency"),
		Namespace:         aws.String("AWS/ApiGateway"),
		Period:            aws.Int64(60),
		Statistic:         aws.String(cloudwatch.StatisticMaximum),
		Tags: []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		},
		Threshold: &props.LatencyThresholdMs,
		Unit:      aws.String(cloudwatch.StandardUnitMilliseconds),
	}

	if _, err := client.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}

	// Many fields are the same - actions, comparison operator, dimensions, namespace, tags
	input.AlarmDescription = aws.String(fmt.Sprintf(
		"API Gateway %s is reporting 5XX internal errors. See: %s#%s",
		props.ApiName, alarmRunbook, props.ApiName))
	input.AlarmName = aws.String(fmt.Sprintf("Panther-%s-%s", gatewayErrorAlarm, props.ApiName))
	input.EvaluationPeriods = aws.Int64(1)
	input.MetricName = aws.String("5XXError")
	input.Period = aws.Int64(300)
	input.Statistic = aws.String(cloudwatch.StatisticSum)
	input.Threshold = aws.Float64(float64(props.ErrorThreshold))
	input.Unit = aws.String(cloudwatch.StandardUnitCount)

	if _, err := client.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}

	return nil
}

func deleteGatewayAlarmGroup(physicalID string) error {
	// PhysicalID: custom:alarms:api:$API_NAME
	split := strings.Split(physicalID, ":")
	apiName := split[len(split)-1]

	alarmNames := []string{
		fmt.Sprintf("Panther-%s-%s", gatewayLatencyAlarm, apiName),
		fmt.Sprintf("Panther-%s-%s", gatewayErrorAlarm, apiName),
	}

	zap.L().Info("deleting metric alarms", zap.Strings("alarmNames", alarmNames))
	_, err := getCloudWatchClient().DeleteAlarms(&cloudwatch.DeleteAlarmsInput{
		AlarmNames: aws.StringSlice(alarmNames)})
	return err
}
