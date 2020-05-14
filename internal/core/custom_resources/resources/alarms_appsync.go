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
	var props AppSyncAlarmProperties
	if err := parseProperties(event.ResourceProperties, &props); err != nil {
		return "", nil, err
	}

	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		return "custom:alarms:appsync:" + props.APIID, nil, putAppSyncAlarmGroup(props)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteAppSyncAlarmGroup(event.PhysicalResourceID)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putAppSyncAlarmGroup(props AppSyncAlarmProperties) error {
	client := getCloudWatchClient()
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmActions: []*string{&props.AlarmTopicArn},
		AlarmDescription: aws.String(fmt.Sprintf(
			"AppSync %s has elevated 4XX errors. See: %s#%s",
			props.APIName, alarmRunbook, props.APIName)),
		AlarmName:          aws.String(fmt.Sprintf("Panther-%s-%s", appSyncClientErrorAlarm, props.APIName)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String("GraphQLAPIId"), Value: &props.APIID},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String("4XXError"),
		Namespace:         aws.String("AWS/AppSync"),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Tags: []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		},
		Threshold:        aws.Float64(float64(props.ClientErrorThreshold)),
		TreatMissingData: aws.String("notBreaching"),
		Unit:             aws.String(cloudwatch.StandardUnitCount),
	}

	zap.L().Info("putting metric alarm", zap.String("alarmName", *input.AlarmName))
	if _, err := client.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}

	input.AlarmDescription = aws.String(fmt.Sprintf(
		"AppSync %s is reporting server errors. See: %s#%s",
		props.APIName, alarmRunbook, props.APIName))
	input.AlarmName = aws.String(fmt.Sprintf("Panther-%s-%s", appSyncServerErrorAlarm, props.APIName))
	input.MetricName = aws.String("5XXError")
	input.Threshold = aws.Float64(float64(props.ServerErrorThreshold))

	zap.L().Info("putting metric alarm", zap.String("alarmName", *input.AlarmName))
	if _, err := client.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}

	return nil
}

func deleteAppSyncAlarmGroup(physicalID string) error {
	// PhysicalID: custom:alarms:appsync:$API_NAME
	split := strings.Split(physicalID, ":")
	if len(split) < 4 {
		zap.L().Warn("invalid physicalID - skipping delete")
		return nil
	}
	apiID := split[3]

	alarmNames := []string{
		fmt.Sprintf("Panther-%s-%s", appSyncClientErrorAlarm, apiID),
		fmt.Sprintf("Panther-%s-%s", appSyncServerErrorAlarm, apiID),
	}

	zap.L().Info("deleting metric alarms", zap.Strings("alarmNames", alarmNames))
	_, err := getCloudWatchClient().DeleteAlarms(&cloudwatch.DeleteAlarmsInput{
		AlarmNames: aws.StringSlice(alarmNames)})
	return err
}
