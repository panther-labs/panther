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
	"time"

	"github.com/aws/aws-sdk-go/aws"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

var (
	pagerDutyEndpoint  = "https://events.pagerduty.com/v2/enqueue"
	triggerEventAction = "trigger"
)

func pantherSeverityToPagerDuty(severity *string) (*string, *AlertDeliveryError) {
	switch *severity {
	case "INFO", "LOW":
		return aws.String("info"), nil
	case "MEDIUM":
		return aws.String("warning"), nil
	case "HIGH":
		return aws.String("error"), nil
	case "CRITICAL":
		return aws.String("critical"), nil
	default:
		return nil, &AlertDeliveryError{Message: "unknown severity" + aws.StringValue(severity)}
	}
}

// PagerDuty sends an alert to a pager duty integration endpoint.
func (client *OutputClient) PagerDuty(alert *alertmodels.Alert, config *outputmodels.PagerDutyConfig) *AlertDeliveryError {
	severity, err := pantherSeverityToPagerDuty(alert.Severity)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"summary":   generateAlertTitle(alert),
		"severity":  aws.StringValue(severity),
		"timestamp": alert.CreatedAt.Format(time.RFC3339),
		"source":    "pantherlabs",
		"custom_details": map[string]string{
			"description": aws.StringValue(alert.PolicyDescription),
			"runbook":     aws.StringValue(alert.Runbook),
		},
	}

	pagerDutyRequest := map[string]interface{}{
		"payload":      payload,
		"routing_key":  *config.IntegrationKey,
		"event_action": triggerEventAction,
	}

	postInput := &PostInput{
		url:  &pagerDutyEndpoint,
		body: pagerDutyRequest,
	}

	return client.httpWrapper.post(postInput)
}
