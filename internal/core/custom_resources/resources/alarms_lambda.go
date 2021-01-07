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
	lambdaLoggedErrorAlarm    = "LambdaLoggedErrors"
	lambdaLoggedWarnAlarm     = "LambdaLoggedWarns"
	lambdaMemoryAlarm         = "LambdaHighMemory"
	lambdaExecutionErrorAlarm = "LambdaExecutionErrors"
	lambdaDurationAlarm       = "LambdaHighDuration"
	lambdaThrottleAlarm       = "LambdaThrottles"
	lambdaCompositeAlarm      = "LambdaCompositeAlarm"
)

type LambdaAlarmProperties struct {
	AlarmTopicArn      string `validate:"required"`
	FunctionName       string `validate:"required"`
	FunctionMemoryMB   int    `json:",string" validate:"min=128"`
	FunctionTimeoutSec int    `json:",string" validate:"min=1"`

	// These are pointers because we have to distinguish 0 from not specified
	LoggedErrorThreshold    *int `json:",string" validate:"omitempty,min=0"`
	LoggedWarnThreshold     *int `json:",string" validate:"omitempty,min=0"`
	ExecutionErrorThreshold *int `json:",string" validate:"omitempty,min=0"`
	ThrottleThreshold       *int `json:",string" validate:"omitempty,min=0"`
}

func customLambdaAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props LambdaAlarmProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		// Set defaults
		if props.LoggedErrorThreshold == nil {
			props.LoggedErrorThreshold = aws.Int(0)
		}
		if props.LoggedWarnThreshold == nil {
			props.LoggedWarnThreshold = aws.Int(25)
		}
		if props.ExecutionErrorThreshold == nil {
			props.ExecutionErrorThreshold = aws.Int(0)
		}
		if props.ThrottleThreshold == nil {
			props.ThrottleThreshold = aws.Int(5)
		}

		return "custom:alarms:lambda:" + props.FunctionName, nil, putLambdaAlarmGroup(props)

	case cfn.RequestDelete:
		// Composite alarm must be deleted first
		if err := deleteAlarms(event.PhysicalResourceID, lambdaCompositeAlarm); err != nil {
			return event.PhysicalResourceID, nil, err
		}

		return event.PhysicalResourceID, nil, deleteAlarms(event.PhysicalResourceID,
			lambdaLoggedErrorAlarm, lambdaLoggedWarnAlarm, lambdaMemoryAlarm,
			lambdaExecutionErrorAlarm, lambdaDurationAlarm, lambdaThrottleAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

// putLambdaAlarmGroup creates the standard set of alarms for all lambdas
//
// The lambda alarms are often correlated.
// For example, a lambda can fail before logging is enabled, so we alarm on that.
// We also alarm when a lambda runs, logs an informative error and fails.
// If paging is tied to both alarms and a lambda runs, logs and error and fails
// the 2 pages are generated (not good). Both alarms are needed because
// the lambda may fail before logging is running. There are also other
// alarms that can be generated for different reasons.
// To avoid multiple pages to oncall, a composite alarm over
// all the primitive alarms is created and associated with the SNS topic.
// The supporting alarms exists so that root cause can be easily
// identified but these alarms do not generate pages.
//
// Logged errors/warns/memory are based on metric filters, hence the Panther namespace.
// See also the Custom::LambdaMetricFilters resource
// Metric filters do not have units, so neither can their alarms
func putLambdaAlarmGroup(props LambdaAlarmProperties) error {
	var alarmDescriptions []alarmDescription // collected for composite alarms
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmDescription: aws.String(fmt.Sprintf(
			"Lambda function %s is logging errors. See: %s#%s",
			props.FunctionName, alarmRunbook, props.FunctionName)),
		AlarmName: aws.String(
			fmt.Sprintf("Panther-%s-%s", lambdaLoggedErrorAlarm, props.FunctionName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		EvaluationPeriods:  aws.Int64(1),
		MetricName:         aws.String(props.FunctionName + "-errors"),
		Namespace:          aws.String("Panther"),
		Period:             aws.Int64(300),
		Statistic:          aws.String(cloudwatch.StatisticSum),
		Threshold:          aws.Float64(float64(*props.LoggedErrorThreshold)),
	}
	if err := putMetricAlarm(input); err != nil {
		return err
	}
	// collect for composite alarm
	alarmDescriptions = append(alarmDescriptions, alarmDescription{
		name:        *input.AlarmName,
		description: *input.AlarmDescription})

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Lambda function %s is logging warnings. See: %s#%s",
		props.FunctionName, alarmRunbook, props.FunctionName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", lambdaLoggedWarnAlarm, props.FunctionName))
	input.MetricName = aws.String(props.FunctionName + "-warns")
	input.Threshold = aws.Float64(float64(*props.LoggedWarnThreshold))
	if err := putMetricAlarm(input); err != nil {
		return err
	}
	// collect for composite alarm
	alarmDescriptions = append(alarmDescriptions, alarmDescription{
		name:        *input.AlarmName,
		description: *input.AlarmDescription})

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Lambda function %s is using more than 90%% of its allotted memory. See: %s#%s",
		props.FunctionName, alarmRunbook, props.FunctionName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", lambdaMemoryAlarm, props.FunctionName))
	input.MetricName = aws.String(props.FunctionName + "-memory")
	input.Statistic = aws.String(cloudwatch.StatisticMaximum)
	input.Threshold = aws.Float64(float64(props.FunctionMemoryMB) * 0.9)
	if err := putMetricAlarm(input); err != nil {
		return err
	}
	// collect for composite alarm
	alarmDescriptions = append(alarmDescriptions, alarmDescription{
		name:        *input.AlarmName,
		description: *input.AlarmDescription})

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Lambda function %s is failing. See: %s#%s",
		props.FunctionName, alarmRunbook, props.FunctionName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", lambdaExecutionErrorAlarm, props.FunctionName))
	input.Dimensions = []*cloudwatch.Dimension{
		{Name: aws.String("FunctionName"), Value: &props.FunctionName},
	}
	input.MetricName = aws.String("Errors")
	input.Namespace = aws.String("AWS/Lambda")
	input.Statistic = aws.String(cloudwatch.StatisticSum)
	input.Threshold = aws.Float64(float64(*props.ExecutionErrorThreshold))
	input.Unit = aws.String(cloudwatch.StandardUnitCount)
	if err := putMetricAlarm(input); err != nil {
		return err
	}
	// collect for composite alarm
	alarmDescriptions = append(alarmDescriptions, alarmDescription{
		name:        *input.AlarmName,
		description: *input.AlarmDescription})

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Lambda function %s is being throttled. See: %s#%s",
		props.FunctionName, alarmRunbook, props.FunctionName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", lambdaThrottleAlarm, props.FunctionName))
	input.MetricName = aws.String("Throttles")
	input.Threshold = aws.Float64(float64(*props.ThrottleThreshold))
	if err := putMetricAlarm(input); err != nil {
		return err
	}
	// collect for composite alarm
	alarmDescriptions = append(alarmDescriptions, alarmDescription{
		name:        *input.AlarmName,
		description: *input.AlarmDescription})

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"Lambda function %s is using more than 90%% of its allotted execution time. See: %s#%s",
		props.FunctionName, alarmRunbook, props.FunctionName))
	input.AlarmName = aws.String(
		fmt.Sprintf("Panther-%s-%s", lambdaDurationAlarm, props.FunctionName))
	input.MetricName = aws.String("Duration")
	input.Statistic = aws.String(cloudwatch.StatisticMaximum)
	input.Threshold = aws.Float64(float64(props.FunctionTimeoutSec) * 1000 * 0.9)
	input.Unit = aws.String(cloudwatch.StandardUnitMilliseconds)
	input.EvaluationPeriods = aws.Int64(3)
	if err := putMetricAlarm(input); err != nil {
		return err
	}
	// collect for composite alarm
	alarmDescriptions = append(alarmDescriptions, alarmDescription{
		name:        *input.AlarmName,
		description: *input.AlarmDescription})

	// the putCompositeAlarm will populate the AlarmDescription and AlarmRule fields.
	compositeInput := &cloudwatch.PutCompositeAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmName:    aws.String(fmt.Sprintf("Panther-%s-%s", lambdaCompositeAlarm, props.FunctionName)),
	}
	return putCompositeAlarm(compositeInput, alarmDescriptions)
}
