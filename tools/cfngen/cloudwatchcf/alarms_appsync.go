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

type AppSyncAlarm struct {
	Alarm
}

func NewAppSyncAlarm(graphQlID, alarmType, metricName, message string, resource map[interface{}]interface{},
	config *Config) (alarm *AppSyncAlarm) {

	const (
		metricDimension = "GraphQLAPIId"
		metricNamespace = "AWS/AppSync"
	)
	appSyncName := getResourceProperty("Name", resource)
	alarmName := AlarmName(alarmType, appSyncName)
	alarm = &AppSyncAlarm{
		Alarm: *NewAlarm(alarmName,
			fmt.Sprintf("AppSync %s %s. See: %s#%s", appSyncName, message, documentationURL, appSyncName),
			config.snsTopicArn),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: graphQlID}})
	return alarm
}

func generateAppSyncAlarms(resource map[interface{}]interface{}, config *Config) (alarms []*Alarm) {
	// this one uses a dynamically generated metric name we get out of the stackOutputs, we only expect 1 in this application
	const graphQlIDKey = "WebApplicationGraphqlApiId"
	var graphQlID string
	if id, found := config.stackOutputs[graphQlIDKey]; found {
		graphQlID = id
	} else {
		panic(fmt.Sprintf("Missing expected %s key in %#v", graphQlIDKey, resource))
	}

	// NOTE: these metrics appear to have no units

	// server errors
	alarms = append(alarms, NewAppSyncAlarm(graphQlID, "AppSyncServerError", "5XXError",
		"is failing", resource, config).SumNoUnitsThreshold(0, 60*5))

	// client errors, here we are concerned with surfacing bugs in the Panther UI as it talks to AppSync
	alarms = append(alarms, NewAppSyncAlarm(graphQlID, "AppSyncClientError", "4XXError",
		"has has elevated 4XX errors", resource, config).SumNoUnitsThreshold(20, 60*5) /* tolerate a few client errors */)

	// latency
	alarms = append(alarms, NewAppSyncAlarm(graphQlID, "AppSyncHighLatency", "Latency",
		"is experience high latency", resource, config).MaxNoUnitsThreshold(1000, 60).EvaluationPeriods(5))

	return alarms
}
