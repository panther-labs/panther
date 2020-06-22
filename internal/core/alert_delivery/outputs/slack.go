package outputs

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

	"github.com/aws/aws-sdk-go/aws"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

// Severity colors match those in the Panther UI
var severityColors = map[string]string{
	"CRITICAL": "#425a70",
	"HIGH":     "#cb2e2e",
	"MEDIUM":   "#d9822b",
	"LOW":      "#f7d154",
	"INFO":     "#47b881",
}

// Slack sends an alert to a slack channel.
func (client *OutputClient) Slack(alert *alertmodels.Alert, config *outputmodels.SlackConfig) *AlertDeliveryError {
	messageField := fmt.Sprintf("<%s|%s>",
		generateURL(alert),
		"Click here to view in the Panther UI")
	fields := []map[string]interface{}{
		{
			"value": messageField,
			"short": false,
		},
		{
			"title": "Runbook",
			"value": aws.StringValue(alert.Runbook),
			"short": false,
		},
		{
			"title": "Severity",
			"value": alert.Severity,
			"short": true,
		},
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"fallback": generateAlertTitle(alert),
				"color":    severityColors[alert.Severity],
				"title":    generateAlertTitle(alert),
				"fields":   fields,
			},
		},
	}
	postInput := &PostInput{
		url:  config.WebhookURL,
		body: payload,
	}

	return client.httpWrapper.post(postInput)
}
