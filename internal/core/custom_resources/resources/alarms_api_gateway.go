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
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"go.uber.org/zap"
)

const (
	alarmRunbook = "https://docs.runpanther.io/operations/runbooks"

	gatewayLatencyAlarm = "ApiGatewayHighIntegrationLatency"
	gatewayErrorAlarm   = "ApiGatewayServerErrors"
)

type APIGatewayAlarmProperties struct {
	APIName            string  `json:"ApiName" validate:"required"`
	AlarmTopicArn      string  `validate:"required"`
	ErrorThreshold     int     `json:",string" validate:"omitempty,min=0"`
	LatencyThresholdMs float64 `json:",string" validate:"omitempty,min=100"`
}

// Add metric filters to a Lambda function's CloudWatch log group
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
		return event.PhysicalResourceID, nil, deleteGatewayAlarmGroup(event.PhysicalResourceID)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putGatewayAlarmGroup(props APIGatewayAlarmProperties) error {
	client := getCloudWatchClient()
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"API Gateway %s is experiencing high integration latency. See: %s#%s",
			props.APIName, alarmRunbook, props.APIName)),
		AlarmName:          aws.String(fmt.Sprintf("Panther-%s-%s", gatewayLatencyAlarm, props.APIName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("Name"), Value: &props.APIName},
		},
		EvaluationPeriods: aws.Int64(5),
		MetricName:        aws.String("IntegrationLatency"),
		Namespace:         aws.String("AWS/ApiGateway"),
		Period:            aws.Int64(60),
		Statistic:         aws.String(cloudwatch.StatisticMaximum),
		Tags: []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		},
		Threshold:        &props.LatencyThresholdMs,
		TreatMissingData: aws.String("notBreaching"),
		Unit:             aws.String(cloudwatch.StandardUnitMilliseconds),
	}

	zap.L().Info("putting metric alarm", zap.String("alarmName", *input.AlarmName))
	if _, err := client.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}

	// Many fields are the same - actions, comparison, dimensions, namespace, tags, treatMissingData
	input.AlarmDescription = aws.String(fmt.Sprintf(
		"API Gateway %s is reporting 5XX internal errors. See: %s#%s",
		props.APIName, alarmRunbook, props.APIName))
	input.AlarmName = aws.String(fmt.Sprintf("Panther-%s-%s", gatewayErrorAlarm, props.APIName))
	input.EvaluationPeriods = aws.Int64(1)
	input.MetricName = aws.String("5XXError")
	input.Period = aws.Int64(300)
	input.Statistic = aws.String(cloudwatch.StatisticSum)
	input.Threshold = aws.Float64(float64(props.ErrorThreshold))
	input.Unit = aws.String(cloudwatch.StandardUnitCount)

	zap.L().Info("putting metric alarm", zap.String("alarmName", *input.AlarmName))
	if _, err := client.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}

	return nil
}

func deleteGatewayAlarmGroup(physicalID string) error {
	// PhysicalID: custom:alarms:api:$API_NAME
	split := strings.Split(physicalID, ":")
	if len(split) < 4 {
		zap.L().Warn("invalid physicalID - skipping delete")
		return nil
	}
	apiName := split[3]

	alarmNames := []string{
		fmt.Sprintf("Panther-%s-%s", gatewayLatencyAlarm, apiName),
		fmt.Sprintf("Panther-%s-%s", gatewayErrorAlarm, apiName),
	}

	zap.L().Info("deleting metric alarms", zap.Strings("alarmNames", alarmNames))
	_, err := getCloudWatchClient().DeleteAlarms(&cloudwatch.DeleteAlarmsInput{
		AlarmNames: aws.StringSlice(alarmNames)})
	return err
}
