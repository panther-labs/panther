package cloudwatchcf

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
)

type LambdaAlarm struct {
	Alarm
	lambdaName string
}

func NewLambdaAlarm(alarmType, metricName, message string, resource map[interface{}]interface{},
	config *Config) (alarm *LambdaAlarm) {

	const (
		metricDimension = "FunctionName"
		metricNamespace = "AWS/Lambda"
	)
	lambdaName := getResourceProperty(metricDimension, resource)
	alarmName := AlarmName(alarmType, lambdaName)
	alarm = &LambdaAlarm{
		Alarm: *NewAlarm(alarmName,
			fmt.Sprintf("Lambda %s %s. See: %s#%s", lambdaName, message, documentationURL, lambdaName),
			config.snsTopicArn),
		lambdaName: lambdaName,
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: alarm.lambdaName}})
	return alarm
}

type LambdaMetricFilterAlarm struct {
	LambdaAlarm
}

func NewLambdaMetricFilterAlarm(alarmType, metricName, message string, resource map[interface{}]interface{},
	config *Config) (alarm *LambdaMetricFilterAlarm) {

	alarm = &LambdaMetricFilterAlarm{
		LambdaAlarm: *NewLambdaAlarm(alarmType, "", message, resource, config),
	}
	alarm.Alarm.Metric(metricFilterNamespace, LambdaMetricFilterName(alarm.lambdaName, metricName), []MetricDimension{})
	return alarm
}

func generateLambdaAlarms(resource map[interface{}]interface{}, config *Config) (alarms []*Alarm) {
	// errors
	alarms = append(alarms, NewLambdaAlarm("LambdaErrors", "Errors",
		"is failing", resource, config).SumCountThreshold(0, 60*5))

	// throttles
	alarms = append(alarms, NewLambdaAlarm("LambdaThrottles", "Throttles",
		"is being throttled", resource, config).SumCountThreshold(5, 60*5) /* tolerate a few throttles before alarming */)

	// errors from metric filter (application logs)
	// NOTE: it is important to not set units because the metric filter values have no units
	alarms = append(alarms, NewLambdaMetricFilterAlarm("LambdaApplicationErrors", lambdaErrorsMetricFilterName,
		"is failing", resource, config).SumNoUnitsThreshold(0, 60*5))

	// warns from metric filter (application logs)
	// NOTE: it is important to not set units because the metric filter values have no units
	alarms = append(alarms, NewLambdaMetricFilterAlarm("LambdaApplicationWarns", lambdaWarnsMetricFilterName,
		"is warning", resource, config).SumNoUnitsThreshold(5, 60*5) /* tolerate a few warnings before alarming */)

	// high water mark memory warning from metric filter
	const memorySizeKey = "MemorySize"
	lambdaMem := getResourceFloat32Property(memorySizeKey, resource)
	const highMemThreshold float32 = 0.9
	highMemMessage := fmt.Sprintf("is using more than %d%% of available memory (%dMB)", (int)(highMemThreshold*100.0), (int)(lambdaMem))
	// NOTE: it is important to not set units because the metric filter values have no units
	alarms = append(alarms, NewLambdaMetricFilterAlarm("LambdaHighMemoryWarn", lambdaMemoryMetricFilterName,
		// 15 min sustained duration
		highMemMessage, resource, config).MaxNoUnitsThreshold(lambdaMem*highMemThreshold, 60*5).EvaluationPeriods(3))

	// high water mark execution time warning from standard metric
	const timeoutKey = "Timeout"
	lambdaTimeout := getResourceFloat32Property(timeoutKey, resource)
	lambdaTimeout *= 1000 // to milliseconds to match metric units
	const highTimeThreshold float32 = 0.9
	timeOutMessage := fmt.Sprintf("is using more than %d%% of available execution time (%dmsec)",
		(int)(highTimeThreshold*100.0), (int)(lambdaTimeout))
	alarms = append(alarms, NewLambdaAlarm("LambdaHighExecutionTimeWarn", "Duration",
		// 15 min sustained duration
		timeOutMessage, resource, config).MaxMillisecondsThreshold(lambdaTimeout*highTimeThreshold, 60*5).EvaluationPeriods(3))

	return alarms
}
