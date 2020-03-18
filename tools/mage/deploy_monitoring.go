package mage

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
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	monitoringStack    = "panther-app-monitoring"
	monitoringTemplate = "deployments/monitoring.yml"
)

// The caller is responsible for generating the nested templates
func deployMonitoring(awsSession *session.Session, bucket string, backendOutputs map[string]string, config *PantherConfig) {
	params := map[string]string{
		"AlarmTopicArn":        config.MonitoringParameterValues.AlarmSNSTopicARN,
		"AppsyncId":            backendOutputs["WebApplicationGraphqlApiId"],
		"LoadBalancerFullName": backendOutputs["WebApplicationLoadBalancerFullName"],
	}
	deployTemplate(awsSession, monitoringTemplate, bucket, monitoringStack, params)
}
