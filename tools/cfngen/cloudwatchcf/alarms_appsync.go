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

// CloudFormation parameter name referenced in generated alarm - we only have one appsync instance.
const appsyncParameterName = "AppsyncId"

type AppSyncAlarm struct {
	Alarm
}

func NewAppSyncAlarm(alarmType, metricName, message string, resource map[string]interface{}) (alarm *AppSyncAlarm) {
	const (
		metricDimension = "GraphQLAPIId"
		metricNamespace = "AWS/AppSync"
	)
	appSyncName := getResourceProperty("Name", resource)
	alarmName := AlarmName(alarmType, appSyncName)
	alarm = &AppSyncAlarm{
		Alarm: *NewAlarm(appSyncName, alarmName,
			fmt.Sprintf("AppSync %s %s. See: %s#%s", appSyncName, message, documentationURL, appSyncName)),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{
		{Name: metricDimension, valueRef: &RefString{appsyncParameterName}}})
	return alarm
}

func generateAppSyncAlarms(resource map[string]interface{}) (alarms []*Alarm) {
	// NOTE: these metrics appear to have no units

	// server errors
	alarms = append(alarms, NewAppSyncAlarm("AppSyncServerError", "5XXError",
		"is failing", resource).SumNoUnitsThreshold(0, 60*5))

	// client errors, here we are concerned with surfacing bugs in the Panther UI as it talks to AppSync
	alarms = append(alarms, NewAppSyncAlarm("AppSyncClientError", "4XXError",
		"has has elevated 4XX errors", resource).SumNoUnitsThreshold(20, 60*5) /* tolerate a few client errors */)

	return alarms
}
