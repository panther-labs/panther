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

// CloudFormation parameter name referenced in generated alarm - we only have one load balancer.
const elbParameterName = "LoadBalancerFullName"

type ApplicationELB struct {
	Alarm
}

func NewApplicationELBAlarm(alarmType, metricName, message string, resource map[string]interface{}) *ApplicationELB {
	const (
		metricDimension = "LoadBalancer"
		metricNamespace = "AWS/ApplicationELB"
	)
	loadBalancerName := getResourceProperty("Name", resource)
	alarmName := AlarmName(alarmType, "Web")
	alarm := &ApplicationELB{
		Alarm: *NewAlarm(loadBalancerName, alarmName,
			fmt.Sprintf("ALB %s. See: %s#%s", message, documentationURL, loadBalancerName)),
	}
	alarm.Alarm.Metric(metricNamespace, metricName, []MetricDimension{
		{Name: metricDimension, valueRef: &RefString{elbParameterName}}})
	return alarm
}

func generateApplicationELBAlarms(resource map[string]interface{}) (alarms []*Alarm) {
	// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html
	// NOTE: the Count metrics appear to have no units

	// latency, alarm if there is sustained (5 x 5min period) poor max latency
	alarms = append(alarms, NewApplicationELBAlarm("ELBTargetLatency", "TargetResponseTime",
		"has elevated latency", resource).P95SecondsThreshold(0.5, 60*5).EvaluationPeriods(5))

	// target 4XX errors are important as they may indicate issues with the application
	alarms = append(alarms, NewApplicationELBAlarm("ELBTarget4XXError", "HTTPCode_Target_4XX_Count",
		"has elevated Target 4XX errors", resource).SumNoUnitsThreshold(5, 60*5) /* tolerate a few  errors */)

	// target 5XX errors can indicate misconfiguration or security issues
	alarms = append(alarms, NewApplicationELBAlarm("ELBTarget5XXError", "HTTPCode_Target_5XX_Count",
		"has elevated Target 5XX errors", resource).SumNoUnitsThreshold(0, 60*5))

	// elb 4XX errors are less interesting if exposed to the Internet, but if there are large numbers
	// this could be a security issue, perhaps an attacker probing Panther
	alarms = append(alarms, NewApplicationELBAlarm("ELB4XXError", "HTTPCode_ELB_4XX_Count",
		"has elevated ELB 4XX errors", resource).SumNoUnitsThreshold(20, 60*5) /* tolerate a few  errors */)

	// elb 5XX errors can indicate misconfiguration or security issues
	alarms = append(alarms, NewApplicationELBAlarm("ELB5XXError", "HTTPCode_ELB_5XX_Count",
		"has elevated ELB 5XX errors", resource).SumNoUnitsThreshold(0, 60*5))

	// unhealthy
	alarms = append(alarms, NewApplicationELBAlarm("ELBUnhealthy", "UnHealthyHostCount",
		"has unhealthy hosts", resource).SumNoUnitsThreshold(0, 60*5))

	return alarms
}
