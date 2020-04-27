package cloudwatchcf

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
	"fmt"

	"github.com/panther-labs/panther/tools/config"
)

type LambdaAlarm struct {
	Alarm
	lambdaName string
}

func NewLambdaAlarm(alarmType, metricName, message string, resource map[interface{}]interface{}) *LambdaAlarm {
	const (
		metricDimension = "FunctionName"
		metricNamespace = "AWS/Lambda"
	)
	lambdaName := getResourceProperty(metricDimension, resource)
	alarmName := AlarmName(alarmType, lambdaName)
	alarm := &LambdaAlarm{
		Alarm: *NewAlarm(lambdaName, alarmName,
			fmt.Sprintf("Lambda %s %s. See: %s#%s", lambdaName, message, documentationURL, lambdaName)),
		lambdaName: lambdaName,
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: alarm.lambdaName}})
	return alarm
}

type LambdaMetricFilterAlarm struct {
	LambdaAlarm
}

func NewLambdaMetricFilterAlarm(alarmType, metricName, message string, resource map[interface{}]interface{}) *LambdaMetricFilterAlarm {
	alarm := &LambdaMetricFilterAlarm{
		LambdaAlarm: *NewLambdaAlarm(alarmType, "", message, resource),
	}
	alarm.Alarm.Metric(metricFilterNamespace, LambdaMetricFilterName(alarm.lambdaName, metricName), []MetricDimension{})
	return alarm
}

func generateLambdaAlarms(resource map[interface{}]interface{}, settings *config.PantherConfig) (alarms []*Alarm) {
	// throttles
	alarms = append(alarms, NewLambdaAlarm("LambdaThrottles", "Throttles",
		"is being throttled", resource).SumCountThreshold(5, 60*5) /* tolerate a few throttles before alarming */)

	// errors
	alarms = append(alarms, NewLambdaAlarm("LambdaErrors", "Errors",
		"is failing", resource).SumCountThreshold(0, 60*5).EvaluationPeriods(2))

	// errors from metric filter (application logs)
	// NOTE: it is important to not set units because the metric filter values have no units
	alarms = append(alarms, NewLambdaMetricFilterAlarm("LambdaApplicationErrors", lambdaErrorsMetricFilterName,
		"is failing", resource).SumNoUnitsThreshold(0, 60*5).EvaluationPeriods(2))

	// warns from metric filter (application logs)
	// NOTE: it is important to not set units because the metric filter values have no units
	alarms = append(alarms, NewLambdaMetricFilterAlarm("LambdaApplicationWarns", lambdaWarnsMetricFilterName,
		"is warning", resource).SumNoUnitsThreshold(25, 60*5) /* tolerate a few warnings before alarming */)

	// high water mark memory warning from metric filter
	const memorySizeKey = "MemorySize"
	var lambdaMem float32
	// special case for panther-log-processor because it uses !Ref to allow user to set size: read from config file
	// https://github.com/panther-labs/panther/issues/435
	const pantherLogProcessorLambda = "panther-log-processor"
	if getResourceProperty("FunctionName", resource) == pantherLogProcessorLambda {
		lambdaMem = (float32)(settings.Infra.LogProcessorLambdaMemorySize)
	} else {
		lambdaMem = getResourceFloat32Property(memorySizeKey, resource)
	}

	const highMemThreshold float32 = 0.9
	highMemMessage := fmt.Sprintf("is using more than %d%% of available memory (%dMB)", (int)(highMemThreshold*100.0), (int)(lambdaMem))
	// NOTE: it is important to not set units because the metric filter values have no units
	alarms = append(alarms, NewLambdaMetricFilterAlarm("LambdaHighMemoryWarn", lambdaMemoryMetricFilterName,
		// 15 min sustained duration
		highMemMessage, resource).MaxNoUnitsThreshold(lambdaMem*highMemThreshold, 60*5).EvaluationPeriods(3))

	// high water mark execution time warning from standard metric
	const timeoutKey = "Timeout"
	lambdaTimeout := getResourceFloat32Property(timeoutKey, resource)
	lambdaTimeout *= 1000 // to milliseconds to match metric units
	const highTimeThreshold float32 = 0.9
	timeOutMessage := fmt.Sprintf("is using more than %d%% of available execution time (%dmsec)",
		(int)(highTimeThreshold*100.0), (int)(lambdaTimeout))
	alarms = append(alarms, NewLambdaAlarm("LambdaHighExecutionTimeWarn", "Duration",
		// 15 min sustained duration
		timeOutMessage, resource).MaxMillisecondsThreshold(lambdaTimeout*highTimeThreshold, 60*5).EvaluationPeriods(3))

	return alarms
}
