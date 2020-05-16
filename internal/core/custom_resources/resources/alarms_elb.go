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
	elbClientErrorAlarm       = "ELB4XXErrors"
	elbServerErrorAlarm       = "ELB5XXErrors"
	elbTargetClientErrorAlarm = "ELBTarget4XXErrors"
	elbTargetServerErrorAlarm = "ELBTarget5XXErrors"
	elbTargetLatencyAlarm     = "ELBTargetLatency"
	elbHealthAlarm            = "ELBHealth"
)

type ElbAlarmProperties struct {
	AlarmTopicArn            string `validate:"required"`
	LoadBalancerFriendlyName string `validate:"required"`
	LoadBalancerFullName     string `validate:"required"`

	ClientErrorThreshold    int     `json:",string" validate:"omitempty,min=0"`
	LatencyThresholdSeconds float64 `json:",string" validate:"omitempty,min=0"`
}

func customElbAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	var props ElbAlarmProperties
	if err := parseProperties(event.ResourceProperties, &props); err != nil {
		return "", nil, err
	}

	if props.LatencyThresholdSeconds == 0 {
		props.LatencyThresholdSeconds = 0.5
	}

	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		return "custom:alarms:elb:" + props.LoadBalancerFriendlyName, nil, putElbAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteMetricAlarms(event.PhysicalResourceID,
			elbClientErrorAlarm, elbServerErrorAlarm, elbTargetClientErrorAlarm,
			elbTargetServerErrorAlarm, elbTargetLatencyAlarm, elbHealthAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putElbAlarmGroup(props ElbAlarmProperties) error {
	input := cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"Load balancer %s has elevated 4XX errors (before reaching the target). See: %s#%s",
			props.LoadBalancerFriendlyName, alarmRunbook, props.LoadBalancerFriendlyName)),
		AlarmName: aws.String(
			fmt.Sprintf("Panther-%s-%s", elbClientErrorAlarm, props.LoadBalancerFriendlyName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("LoadBalancer"), Value: &props.LoadBalancerFullName},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String("HTTPCode_ELB_4XX_Count"),
		Namespace:         aws.String("AWS/ApplicationELB"),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Threshold:         aws.Float64(float64(props.ClientErrorThreshold)),
		Unit:              aws.String(cloudwatch.StandardUnitCount),
	}
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Load balancer %s has 5XX errors (before reaching the target). See: %s#%s",
		props.LoadBalancerFriendlyName, alarmRunbook, props.LoadBalancerFriendlyName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", elbServerErrorAlarm, props.LoadBalancerFriendlyName))
	input.MetricName = aws.String("HTTPCode_ELB_5XX_Count")
	input.Threshold = aws.Float64(0)
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Load balancer %s has elevated 4XX errors from its target. See: %s#%s",
		props.LoadBalancerFriendlyName, alarmRunbook, props.LoadBalancerFriendlyName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", elbTargetClientErrorAlarm, props.LoadBalancerFriendlyName))
	input.MetricName = aws.String("HTTPCode_Target_4XX_Count")
	input.Threshold = aws.Float64(float64(props.ClientErrorThreshold))
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Load balancer %s has 5XX errors from its target. See: %s#%s",
		props.LoadBalancerFriendlyName, alarmRunbook, props.LoadBalancerFriendlyName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", elbTargetServerErrorAlarm, props.LoadBalancerFriendlyName))
	input.MetricName = aws.String("HTTPCode_Target_5XX_Count")
	input.Threshold = aws.Float64(0)
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Load balancer %s has unhealthy hosts. See: %s#%s",
		props.LoadBalancerFriendlyName, alarmRunbook, props.LoadBalancerFriendlyName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", elbHealthAlarm, props.LoadBalancerFriendlyName))
	input.MetricName = aws.String("UnHealthyHostCount")
	input.Threshold = aws.Float64(0)
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Load balancer %s has elevated latency. See: %s#%s",
		props.LoadBalancerFriendlyName, alarmRunbook, props.LoadBalancerFriendlyName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", elbTargetLatencyAlarm, props.LoadBalancerFriendlyName))
	input.EvaluationPeriods = aws.Int64(5)
	input.ExtendedStatistic = aws.String("p95")
	input.MetricName = aws.String("TargetResponseTime")
	input.Period = aws.Int64(25 * 60)
	input.Statistic = nil
	input.Threshold = aws.Float64(props.LatencyThresholdSeconds)
	input.Unit = aws.String(cloudwatch.StandardUnitSeconds)
	return putMetricAlarm(input)
}
