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
	"go.uber.org/zap"
)

const (
	memoryFilter      = `[ report_label="REPORT", ..., label="Used:", max_memory_used_value, unit="MB" ]`
	warnFilterGo      = `{ $.level = "warn" }`
	warnFilterPython  = `[ level="[WARN]" ]`
	errorFilterGo     = `{ $.level = "error" }`
	errorFilterPython = `[ level="[ERROR]" ]`
)

type LambdaMetricFiltersProperties struct {
	LambdaRuntime string `validate:"omitempty,oneof=Go Python"`
	LogGroupName  string `validate:"required"`
}

// Add metric filters to a Lambda function's CloudWatch log group
func customLambdaMetricFilters(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	var props LambdaMetricFiltersProperties
	if err := parseProperties(event.ResourceProperties, &props); err != nil {
		return "", nil, err
	}

	// If not specified, use Go as the default Lambda runtime
	if props.LambdaRuntime == "" {
		props.LambdaRuntime = "Go"
	}

	switch event.RequestType {
	case cfn.RequestCreate:
		physicalID, err := putMetricFilterGroup(props.LogGroupName, props.LambdaRuntime)
		return physicalID, nil, err

	case cfn.RequestUpdate:
		var oldProps LambdaMetricFiltersProperties
		if err := parseProperties(event.OldResourceProperties, &oldProps); err == nil {
			if oldProps.LambdaRuntime == "" {
				oldProps.LambdaRuntime = "Go"
			}

			// After filling in default values, the old and new resource properties are the same.
			if props == oldProps {
				zap.L().Info("old and new properties are the same - no changes needed")
				return event.PhysicalResourceID, nil, nil
			}
		}

		// Either the log group or the lambda runtime changed - put new metric filters.
		//
		// If the log group changed, the physicalID will change as well and CFN will automatically
		// request deletion of the old metric filters.
		//
		// If the runtime changed, we will overwrite the existing metric filters with new values
		// (but the same name) and the physicalID will remain the same.
		physicalID, err := putMetricFilterGroup(props.LogGroupName, props.LambdaRuntime)
		return physicalID, nil, err

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteMetricFilterGroup(event.PhysicalResourceID)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func putMetricFilterGroup(logGroup, runtime string) (string, error) {
	lambdaName := lambdaNameFromLogGroup(logGroup)

	// Track max memory usage
	if err := putMetricFilter(logGroup, memoryFilter, lambdaName+"-memory", "$max_memory_used_value"); err != nil {
		return "", err
	}

	// We store successful filter name suffixes at the end of the physicalID.
	// If the create fails halfway through, CFN will rollback and request deletion for the resource.
	// This way, we can delete whichever filters have been added so far.
	physicalID := fmt.Sprintf("custom:metric-filters:%s:memory", logGroup)

	// Logged warnings
	warnFilter := warnFilterGo
	if runtime == "Python" {
		warnFilter = warnFilterPython
	}
	if err := putMetricFilter(logGroup, warnFilter, lambdaName+"-warns", "1"); err != nil {
		return physicalID, err
	}
	physicalID += "/warns"

	// Logged errors
	errorFilter := errorFilterGo
	if runtime == "Python" {
		errorFilter = errorFilterPython
	}
	if err := putMetricFilter(logGroup, errorFilter, lambdaName+"-errors", "1"); err != nil {
		return physicalID, err
	}

	return physicalID + "/errors", nil
}

// For metric/filter names, use the Lambda function name as a prefix
// "/aws/lambda/panther-alert-delivery" => "panther-alert-delivery"
func lambdaNameFromLogGroup(logGroupName string) string {
	split := strings.Split(logGroupName, "/")
	return split[len(split)-1]
}

func putMetricFilter(logGroupName, filterPattern, metricName, metricValue string) error {
	zap.L().Info("creating metric filter", zap.String("metricName", metricName))
	_, err := getCloudWatchLogsClient().PutMetricFilter(&cloudwatchlogs.PutMetricFilterInput{
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
// The physicalID is of the form custom:metric-filters:$LOG_GROUP_NAME:$FILTER1/$FILTER2/...
func deleteMetricFilterGroup(physicalID string) error {
	split := strings.Split(physicalID, ":")
	if len(split) != 4 {
		// If creation fails before any filters were created, the resourceID will be "error"
		zap.L().Warn("åinvalid physicalResourceId - skipping delete")
		return nil
	}

	logGroupName := split[2]
	lambdaName := lambdaNameFromLogGroup(logGroupName)

	for _, filterSuffix := range strings.Split(split[3], "/") {
		filterName := lambdaName + "-" + filterSuffix
		zap.L().Info("deleting metric filter", zap.String("name", filterName))
		_, err := getCloudWatchLogsClient().DeleteMetricFilter(&cloudwatchlogs.DeleteMetricFilterInput{
			FilterName:   &filterName,
			LogGroupName: &logGroupName,
		})

		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == cloudwatchlogs.ErrCodeResourceNotFoundException {
				zap.L().Info("metric filter has already been deleted")
				continue
			}
			return fmt.Errorf("failed to delete %s metric filter %s: %v", logGroupName, filterName, err)
		}
	}

	return nil
}
