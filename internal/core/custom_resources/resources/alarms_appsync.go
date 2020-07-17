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
	appSyncClientErrorAlarm = "AppSyncClientErrors"
	appSyncServerErrorAlarm = "AppSyncServerErrors"
)

type AppSyncAlarmProperties struct {
	APIID                string `json:"ApiId" validate:"required"`
	APIName              string `json:"ApiName" validate:"required"`
	AlarmTopicArn        string `validate:"required"`
	ClientErrorThreshold int    `json:",string" validate:"omitempty,min=0"`
	ServerErrorThreshold int    `json:",string" validate:"omitempty,min=0"`
}

func customAppSyncAlarms(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props AppSyncAlarmProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}
		return "custom:alarms:appsync:" + props.APIID, nil, putAppSyncAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteAlarms(event.PhysicalResourceID,
			appSyncClientErrorAlarm, appSyncServerErrorAlarm)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putAppSyncAlarmGroup(props AppSyncAlarmProperties) error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"AppSync %s has elevated 4XX errors. See: %s#%s",
			props.APIName, alarmRunbook, props.APIName)),
		AlarmName:          aws.String(fmt.Sprintf("Panther-%s-%s", appSyncClientErrorAlarm, props.APIID)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("GraphQLAPIId"), Value: &props.APIID},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String("4XXError"),
		Namespace:         aws.String("AWS/AppSync"),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Threshold:         aws.Float64(float64(props.ClientErrorThreshold)),
		Unit:              aws.String(cloudwatch.StandardUnitCount),
	}
	if err := putMetricAlarm(input); err != nil {
		return err
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"AppSync %s is reporting server errors. See: %s#%s",
		props.APIName, alarmRunbook, props.APIName))
	input.AlarmName = aws.String(fmt.Sprintf("Panther-%s-%s", appSyncServerErrorAlarm, props.APIID))
	input.MetricName = aws.String("5XXError")
	input.Threshold = aws.Float64(float64(props.ServerErrorThreshold))
	return putMetricAlarm(input)
}
