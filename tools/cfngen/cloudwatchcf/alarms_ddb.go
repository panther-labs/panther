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

type DynamoDBAlarm struct {
	Alarm
}

func NewDynamoDBAlarm(operation, alarmType, metricName, message string, resource map[string]interface{}) *DynamoDBAlarm {
	const (
		metricDimension = "TableName"
		metricNamespace = "AWS/DynamoDB"
	)
	tableName := getResourceProperty(metricDimension, resource)
	alarmName := AlarmName(alarmType, tableName)
	alarm := &DynamoDBAlarm{
		Alarm: *NewAlarm(tableName, alarmName,
			fmt.Sprintf("DynamoDB %s %s %s operations. See: %s#%s", tableName, message, operation, documentationURL, tableName)),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: tableName},
		{Name: "Operation", Value: operation}})
	return alarm
}

func generateDynamoDBAlarms(resource map[string]interface{}) (alarms []*Alarm) {
	// NOTE: error metrics appear to have no units
	operations := []string{"GetItem", "PutItem", "UpdateItem", "Scan", "BatchWriteItem"}

	for _, operation := range operations {
		// errors
		alarms = append(alarms, NewDynamoDBAlarm(operation, "DDB"+operation+"Error", "SystemErrors",
			"is failing", resource).SumNoUnitsThreshold(0, 60*5))

		// throttles
		alarms = append(alarms, NewDynamoDBAlarm(operation, "DDB"+operation+"Throttle", "ThrottledRequests",
			"is throttling", resource).SumNoUnitsThreshold(0, 60*5))

		// latency
		alarms = append(alarms, NewDynamoDBAlarm(operation, "DDB"+operation+"HighLatency", "SuccessfulRequestLatency",
			"is experiencing high latency", resource).MaxMillisecondsThreshold(1000, 60).EvaluationPeriods(5))
	}

	return alarms
}
