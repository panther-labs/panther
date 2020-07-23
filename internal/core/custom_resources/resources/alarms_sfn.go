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
)

const (
	sfnFailedExecutionsAlarm = "SFNExecutionsFailed"
)

type SFNAlarmProperties struct {
	AlarmTopicArn   string `validate:"required"`
	StateMachineArn string `validate:"required"`

	stateMachineName string
}

func customStateMachineAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props SFNAlarmProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		props.stateMachineName = stateMachineName(props.StateMachineArn)

		return "custom:alarms:sfn:" + props.stateMachineName, nil, putSfnAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteAlarms(event.PhysicalResourceID, sfnFailedExecutionsAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

// Parse the name out of the state machine arn or the custom resource physicalID.
//
// Either way, the name will be after the last colon
func stateMachineName(arn string) string {
	split := strings.Split(arn, ":")
	return split[len(split)-1]
}

func putSfnAlarmGroup(props SFNAlarmProperties) error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"State machine %s is failing. See: %s#%s",
			props.stateMachineName, alarmRunbook, props.stateMachineName)),
		AlarmName: aws.String(
			fmt.Sprintf("Panther-%s-%s", sfnFailedExecutionsAlarm, props.stateMachineName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("StateMachineArn"), Value: &props.StateMachineArn},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String("ExecutionsFailed"),
		Namespace:         aws.String("AWS/States"),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Threshold:         aws.Float64(0),
		Unit:              aws.String(cloudwatch.StandardUnitCount),
	}
	return putMetricAlarm(input)
}
