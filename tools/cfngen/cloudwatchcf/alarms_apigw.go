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
)

type APIGatewayAlarm struct {
	Alarm
}

func NewAPIGatewayAlarm(alarmType, metricName, message string, resource map[string]interface{}) (alarm *APIGatewayAlarm) {
	const (
		metricDimension = "Name"
		metricNamespace = "AWS/ApiGateway"
	)
	apiGatewayName := getResourceProperty(metricDimension, resource)
	alarmName := AlarmName(alarmType, apiGatewayName)
	alarm = &APIGatewayAlarm{
		Alarm: *NewAlarm(apiGatewayName, alarmName,
			fmt.Sprintf("ApiGateway %s %s. See: %s#%s", apiGatewayName, message, documentationURL, apiGatewayName)),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: apiGatewayName}})
	return alarm
}

func generateAPIGatewayAlarms(resource map[string]interface{}) (alarms []*Alarm) {
	// NOTE: error metrics appear to have no units

	// server errors
	alarms = append(alarms, NewAPIGatewayAlarm("ApiGatewayServerError", "5XXError",
		"is failing", resource).SumNoUnitsThreshold(0, 60*5))

	// client errors are used for signalling internally so we do not alarm on them

	// integration latency
	alarms = append(alarms, NewAPIGatewayAlarm("ApiGatewayHighIntegationLatency", "IntegrationLatency",
		"is experiencing high integration latency", resource).MaxMillisecondsThreshold(1000, 60).EvaluationPeriods(5))

	return alarms
}
