package outputs

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"context"
	"strings"

	jsoniter "github.com/json-iterator/go"

	alertModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

// MsTeams alert send an alert.
func (client *OutputClient) MsTeams(
	ctx context.Context, alert *alertModels.Alert, config *outputModels.MsTeamsConfig) *AlertDeliveryResponse {

	link := "[Click here to view in the Panther UI](" + generateURL(alert) + ").\n"

	// Best effort attempt to marshal Alert Context
	marshaledContext, _ := jsoniter.MarshalToString(alert.Context)

	msTeamsRequestBody := map[string]interface{}{
		"@context": "http://schema.org/extensions",
		"@type":    "MessageCard",
		"text":     generateAlertTitle(alert),
		"sections": []interface{}{
			map[string]interface{}{
				"facts": []interface{}{
					map[string]string{"name": "Description", "value": alert.AnalysisDescription},
					map[string]string{"name": "Runbook", "value": alert.Runbook},
					map[string]string{"name": "Severity", "value": alert.Severity},
					map[string]string{"name": "Tags", "value": strings.Join(alert.Tags, ", ")},
					map[string]string{"name": "AlertContext", "value": marshaledContext},
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

	postInput := &PostInput{
		url:  config.WebhookURL,
		body: msTeamsRequestBody,
	}
	return client.httpWrapper.post(ctx, postInput)
}
