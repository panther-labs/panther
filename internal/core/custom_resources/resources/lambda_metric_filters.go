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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	memoryFilter      = `[ report_label="REPORT", ..., label="Used:", max_memory_used_value, unit="MB" ]`
	warnFilterGo      = `{ $.level = "warn" }`
	warnFilterPython  = `"[WARN]"`
	errorFilterGo     = `{ $.level = "error" }`
	errorFilterPython = `"[ERROR]"`
)

type LambdaMetricFiltersProperties struct {
	LambdaRuntime string `validate:"omitempty,oneof=Go Python"`
	LogGroupName  string `validate:"required"`
}

// Add metric filters to a Lambda function's CloudWatch log group
func customLambdaMetricFilters(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		// If the log group changed, the physicalID will change as well and CFN will automatically
		// request deletion of the old metric filters.
		//
		// If the runtime changed, we will overwrite the existing metric filters with new values
		// (but the same name) and the physicalID will remain the same.
		var props LambdaMetricFiltersProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		// If not specified, use Go as the default Lambda runtime
		if props.LambdaRuntime == "" {
			props.LambdaRuntime = "Go"
		}

		return fmt.Sprintf("custom:metric-filters:" + props.LogGroupName), nil, putMetricFilterGroup(
			props.LogGroupName, props.LambdaRuntime)

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteMetricFilterGroup(event.PhysicalResourceID)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putMetricFilterGroup(logGroup, runtime string) error {
	lambdaName := lambdaNameFromLogGroup(logGroup)

	// Track max memory usage
	if err := putMetricFilter(logGroup, memoryFilter, lambdaName+"-memory", "$max_memory_used_value"); err != nil {
		return err
	}

	// Logged warnings
	warnFilter := warnFilterGo
	if runtime == "Python" {
		warnFilter = warnFilterPython
	}
	if err := putMetricFilter(logGroup, warnFilter, lambdaName+"-warns", "1"); err != nil {
		return err
	}

	// Logged errors
	errorFilter := errorFilterGo
	if runtime == "Python" {
		errorFilter = errorFilterPython
	}
	if err := putMetricFilter(logGroup, errorFilter, lambdaName+"-errors", "1"); err != nil {
		return err
	}

	return nil
}

// For metric/filter names, use the Lambda function name as a prefix
// "/aws/lambda/panther-alert-delivery-api" => "panther-alert-delivery-api"
func lambdaNameFromLogGroup(logGroupName string) string {
	split := strings.Split(logGroupName, "/")
	return split[len(split)-1]
}

func putMetricFilter(logGroupName, filterPattern, metricName, metricValue string) error {
	zap.L().Info("creating metric filter", zap.String("metricName", metricName))
	_, err := cloudWatchLogsClient.PutMetricFilter(&cloudwatchlogs.PutMetricFilterInput{
		FilterName:    &metricName,
		FilterPattern: &filterPattern,
		LogGroupName:  &logGroupName,
		MetricTransformations: []*cloudwatchlogs.MetricTransformation{
			{
				DefaultValue:    aws.Float64(0),
				MetricName:      &metricName,
				MetricNamespace: aws.String("Panther"),
				MetricValue:     &metricValue,
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to put %s metric filter: %v", metricName, err)
	}
	return nil
}

// Delete all filters associated with the custom resource.
//
// The physicalID is of the form custom:metric-filters:$LOG_GROUP_NAME
func deleteMetricFilterGroup(physicalID string) error {
	split := strings.Split(physicalID, ":")
	if len(split) != 3 {
		// If creation fails before any filters were created, the resourceID will be "error"
		zap.L().Warn("invalid physicalResourceId - skipping delete")
		return nil
	}

	logGroupName := split[2]
	lambdaName := lambdaNameFromLogGroup(logGroupName)

	for _, name := range []string{lambdaName + "-memory", lambdaName + "-warns", lambdaName + "-errors"} {
		zap.L().Info("deleting metric filter", zap.String("name", name))
		_, err := cloudWatchLogsClient.DeleteMetricFilter(&cloudwatchlogs.DeleteMetricFilterInput{
			FilterName:   aws.String(name),
			LogGroupName: aws.String(logGroupName),
		})

		if err != nil {
			var awsErr awserr.Error
			if errors.As(err, &awsErr) && awsErr.Code() == cloudwatchlogs.ErrCodeResourceNotFoundException {
				zap.L().Info("metric filter has already been deleted")
				continue
			}
			return fmt.Errorf("failed to delete %s metric filter %s: %v", logGroupName, name, err)
		}
	}

	return nil
}
