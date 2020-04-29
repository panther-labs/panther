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

import "fmt"

type SFNAlarm struct {
	Alarm
}

func NewSFNAlarm(alarmType, metricName, message string, resource map[string]interface{}) *SFNAlarm {
	const (
		metricDimension = "StateMachineArn"
		metricNamespace = "AWS/States"
	)
	stateMachineName := getResourceProperty("StateMachineName", resource)
	stateMachineArn := fmt.Sprintf("arn:${AWS::Partition}:states:${AWS::Region}:${AWS::AccountId}:stateMachine:%s",
		stateMachineName)
	alarmName := AlarmName(alarmType, stateMachineName)
	alarm := &SFNAlarm{
		Alarm: *NewAlarm(stateMachineName, alarmName,
			fmt.Sprintf("State machine %s %s. See: %s#%s", stateMachineName, message, documentationURL, stateMachineName)),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{
		Name:     metricDimension,
		valueSub: &SubString{Sub: stateMachineArn},
	},
	})
	return alarm
}

func generateSFNAlarms(resource map[string]interface{}) []*Alarm {
	return []*Alarm{
		NewSFNAlarm(
			"SFNError",
			"ExecutionsFailed",
			"is failing",
			resource,
		).SumCountThreshold(0, 60*5),
	}
}
