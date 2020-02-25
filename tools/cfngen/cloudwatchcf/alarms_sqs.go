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
	"strings"
)

type SQSAlarm struct {
	Alarm
}

func NewSQSAlarm(queueName, alarmType, metricName, message string, resource map[interface{}]interface{},
	config *Config) (alarm *SQSAlarm) {

	const (
		metricDimension = "QueueName"
		metricNamespace = "AWS/SQS"
	)
	alarmName := AlarmName(alarmType, queueName)
	alarm = &SQSAlarm{
		Alarm: *NewAlarm(alarmName,
			fmt.Sprintf("SQS queue %s %s. See: %s#%s", queueName, message, documentationURL, queueName),
			config.snsTopicArn),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: queueName}})
	return alarm
}

func generateSQSAlarms(resource map[interface{}]interface{}, config *Config) (alarms []*Alarm) {
	queueName := getResourceProperty("QueueName", resource)

	// DLQ qs are special, we alarm on ANY data in q
	if strings.HasSuffix(queueName, "-dlq") {
		referenceQueue := strings.Replace(queueName, "-dlq", "", -1)
		// NOTE: this metric appears to have no units
		alarms = append(alarms, NewSQSAlarm(queueName, "SQSDeadLetters", "ApproximateNumberOfMessagesVisible",
			"has failed items from"+referenceQueue, resource, config).SumNoUnitsThreshold(0, 60*5))
	} else { // regular q's
		// nothing in our queues should be older than 5min
		const tooOldSec float32 = 60.0 * 5.0
		alarms = append(alarms, NewSQSAlarm(queueName, "SQSTooOld", "ApproximateAgeOfOldestMessage",
			"has items not being processed at the expected rate", resource, config).MaxSecondsThreshold(tooOldSec, 60*5))
	}

	return alarms
}
