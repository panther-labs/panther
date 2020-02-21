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

type APIGatewayAlarm struct {
	Alarm
}

func NewAPIGatewayAlarm(alarmType, metricName, message string, resource map[interface{}]interface{},
	config *Config) (alarm *APIGatewayAlarm) {

	const (
		metricDimension = "Name"
		metricNamespace = "AWS/ApiGateway"
	)
	apiGatewayName := getResourceProperty(metricDimension, resource)
	alarmName := AlarmName(alarmType, apiGatewayName)
	alarm = &APIGatewayAlarm{
		Alarm: *NewAlarm(alarmName,
			fmt.Sprintf("ApiGateway %s %s. See: %s#%s", apiGatewayName, message, documentationURL, alarmName),
			config.snsTopicArn),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: apiGatewayName}})
	return alarm
}

func generateAPIGatewayAlarms(resource map[interface{}]interface{}, config *Config) (alarms []*Alarm) {
	// NOTE: error metrics appear to have no units

	// server errors
	alarms = append(alarms, NewAPIGatewayAlarm("ApiGatewayServerError", "5XXError",
		"is failing", resource, config).SumNoUnitsThreshold(0, 60*5))

	// client errors, we currently only use api gw internally so client errors are serious
	alarms = append(alarms, NewAPIGatewayAlarm("ApiGatewayClientError", "4XXError",
		"is failing", resource, config).SumNoUnitsThreshold(0, 60*5))

	// latency
	alarms = append(alarms, NewAPIGatewayAlarm("ApiGatewayHighLatency", "Latency",
		"is experience high latency", resource, config).MaxMillisecondsThreshold(1000, 60).EvaluationPeriods(5))

	// integration latency
	alarms = append(alarms, NewAPIGatewayAlarm("ApiGatewayHighIntegationLatency", "IntegrationLatency",
		"is experience high integration latency", resource, config).MaxMillisecondsThreshold(1000, 60).EvaluationPeriods(5))

	return alarms
}
