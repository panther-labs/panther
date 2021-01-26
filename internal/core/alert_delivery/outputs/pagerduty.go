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
	"context"
	"time"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

const (
	pagerDutyEndpoint  = "https://events.pagerduty.com/v2/enqueue"
	triggerEventAction = "trigger"
)

// PagerDuty sends an alert to a pager duty integration endpoint.
func (client *OutputClient) PagerDuty(
	ctx context.Context,
	alert *deliverymodel.Alert,
	config *outputModels.PagerDutyConfig,
) *AlertDeliveryResponse {

	severity, err := pantherSeverityToPagerDuty(alert.Severity)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"summary":        generateAlertTitle(alert),
		"severity":       severity,
		"timestamp":      alert.CreatedAt.Format(time.RFC3339),
		"source":         "pantherlabs",
		"custom_details": generateNotificationFromAlert(alert),
	}

	pagerDutyRequest := map[string]interface{}{
		"payload":      payload,
		"routing_key":  config.IntegrationKey,
		"event_action": triggerEventAction,
	}

	postInput := &PostInput{
		url:  pagerDutyEndpoint,
		body: pagerDutyRequest,
	}

	return client.httpWrapper.post(ctx, postInput)
}

func pantherSeverityToPagerDuty(severity string) (string, *AlertDeliveryResponse) {
	switch severity {
	case "INFO", "LOW":
		return "info", nil
	case "MEDIUM":
		return "warning", nil
	case "HIGH":
		return "error", nil
	case "CRITICAL":
		return "critical", nil
	default:
		return "", &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    "unknown severity" + severity,
			Permanent:  true, // We don't want to retry alert's that don't have a valid severity
			Success:    false,
		}
	}
}
