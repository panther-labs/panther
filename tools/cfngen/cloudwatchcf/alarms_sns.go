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

type SNSAlarm struct {
	Alarm
}

func NewSNSAlarm(alarmType, metricName, message string, resource map[interface{}]interface{},
	config *Config) (alarm *SNSAlarm) {

	const (
		metricDimension = "TopicName"
		metricNamespace = "AWS/SNS"
	)
	topicName := getResourceProperty(metricDimension, resource)
	alarmName := AlarmName(alarmType, topicName)
	alarm = &SNSAlarm{
		Alarm: *NewAlarm(alarmName,
			fmt.Sprintf("SNS topic %s %s. See: %s#%s", topicName, message, documentationURL, topicName),
			config.snsTopicArn),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: topicName}})
	return alarm
}

func generateSNSAlarms(resource map[interface{}]interface{}, config *Config) (alarms []*Alarm) {
	// errors
	alarms = append(alarms, NewSNSAlarm("SNSError", "NumberOfNotificationsFailed", "is failing",
		resource, config).SumCountThreshold(0, 60*5))

	return alarms
}
