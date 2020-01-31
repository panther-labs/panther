package outputs

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
	"strings"

	"github.com/aws/aws-sdk-go/aws"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

// MsTeams alert send an alert.
func (client *OutputClient) MsTeams(
	alert *alertmodels.Alert, config *outputmodels.MsTeamsConfig) *AlertDeliveryError {

	var tagsItem = aws.StringValueSlice(alert.Tags)

	link := "[Click here to view in the Panther UI](" + policyURLPrefix + aws.StringValue(alert.PolicyID) + ").\n"
	runBook := aws.StringValue(alert.Runbook)
	ruleDescription := aws.StringValue(alert.PolicyDescription)
	severity := aws.StringValue(alert.Severity)
	tags := strings.Join(tagsItem, ", ")

	msTeamsRequestBody := map[string]interface{}{
		"@context": "http://schema.org/extensions",
		"@type":    "MessageCard",
		"text":     generateAlertTitle(alert),
		"sections": []interface{}{
			map[string]interface{}{
				"facts": []interface{}{
					map[string]string{"name": "Description", "value": ruleDescription},
					map[string]string{"name": "Runbook", "value": runBook},
					map[string]string{"name": "Severity", "value": severity},
					map[string]string{"name": "Tags", "value": tags},
				},
				"text": link,
			},
		},
		"potentialAction": []interface{}{
			map[string]interface{}{
				"@type": "OpenUri",
				"name":  "Click here to view in the Panther UI",
				"targets": []interface{}{
					map[string]string{
						"os":  "default",
						"uri": generateURL(alert),
					},
				},
			},
		},
	}

	requestURL := *config.WebhookURL
	postInput := &PostInput{
		url:  requestURL,
		body: msTeamsRequestBody,
	}
	return client.httpWrapper.post(postInput)
}
