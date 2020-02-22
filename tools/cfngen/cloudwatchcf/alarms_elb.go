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

type ApplicationELB struct {
	Alarm
}

func NewApplicationELBAlarm(loadBalancer, alarmType, metricName, message string, resource map[interface{}]interface{},
	config *Config) (alarm *ApplicationELB) {

	const (
		metricDimension = "LoadBalancer"
		metricNamespace = "AWS/ApplicationELB"
	)
	loadBalancerName := getResourceProperty("Name", resource)
	alarmName := AlarmName(alarmType, loadBalancer)
	alarm = &ApplicationELB{
		Alarm: *NewAlarm(alarmName,
			fmt.Sprintf("ALB %s %s. See: %s#%s", loadBalancer, message, documentationURL, loadBalancerName),
			config.snsTopicArn),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{{Name: metricDimension, Value: loadBalancer}})
	return alarm
}

func generateApplicationELBAlarms(resource map[interface{}]interface{}, config *Config) (alarms []*Alarm) {
	// this one uses a dynamically generated metric name we get out of the stackOutputs, we only expect 1 in this application
	const loadBalancerKey = "WebApplicationLoadBalancerFullName"
	var loadBalancer string
	if lb, found := config.stackOutputs[loadBalancerKey]; found {
		loadBalancer = lb
	} else {
		panic(fmt.Sprintf("Missing expected %s key in %#v", loadBalancerKey, resource))
	}

	// NOTE: these metrics appear to have no units

	// target 4XX errors are important as they may indicate issues with the application
	alarms = append(alarms, NewApplicationELBAlarm(loadBalancer, "ELBTargetError", "HTTPCode_Target_4XX_Count",
		"has elevated Target 4XX errors", resource, config).SumNoUnitsThreshold(5, 60*5) /* tolerate a few  errors */)

	// elb 4XX errors are less interesting if exposed to the Internet, but if there are large numbers
	// this could be a security issue, perhaps an attacker probing Panther
	alarms = append(alarms, NewApplicationELBAlarm(loadBalancer, "ELBError", "HTTPCode_ELB_4XX_Count",
		"has elevated ELB 4XX errors", resource, config).SumNoUnitsThreshold(20, 60*5) /* tolerate a few  errors */)

	// latency
	alarms = append(alarms, NewApplicationELBAlarm(loadBalancer, "ELBHighLatency", "TargetResponseLatency",
		"is experience high latency", resource, config).MaxSecondsThreshold(1, 60).EvaluationPeriods(5))

	// unhealthy
	alarms = append(alarms, NewApplicationELBAlarm(loadBalancer, "ELBUnhealthy", "UnHealthyHostCount",
		"has unhealthy hosts", resource, config).SumNoUnitsThreshold(0, 60*5))

	return alarms
}
