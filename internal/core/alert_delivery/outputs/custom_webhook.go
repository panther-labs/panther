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
	"time"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

// CustomWebhook alert send an alert.
func (client *OutputClient) CustomWebhook(
	alert *alertmodels.Alert, config *outputmodels.CustomWebhookConfig) *AlertDeliveryError {

	// Get or generate concrete values
	id := getID(alert)
	name := getDisplayName(alert)
	alertType := getType(alert)
	link := generateURL(alert)
	title := generateAlertTitle(alert)
	description := generateDetailedAlertMessage(alert)
	// Define an empty slice so marshaling returns "[]" instead of "null"
	tags := []*string{}
	if len(alert.Tags) > 0 {
		tags = alert.Tags
	}

	customWebhookAlert := &CustomWebhookAlert{
		ID:          &id,
		Name:        &name,
		Severity:    alert.Severity,
		Type:        &alertType,
		Link:        &link,
		Title:       &title,
		Description: &description,
		Runbook:     alert.Runbook,
		Tags:        tags,
		Version:     alert.PolicyVersionID,
	}

	outputMessage := &CustomWebhookOutputMessage{
		Alert:     *customWebhookAlert,
		CreatedAt: alert.CreatedAt,
	}

	requestURL := *config.WebhookURL
	postInput := &PostInput{
		url: requestURL,
		body: map[string]interface{}{
			"alert":     outputMessage.Alert,
			"createdAt": outputMessage.CreatedAt,
		},
	}
	return client.httpWrapper.post(postInput)
}

//CustomWebhookAlert describes the details of an alert in the Custom Webhook message
type CustomWebhookAlert struct {
	// [REQUIRED] Either AlertID or PolicyID depending on the alert type
	ID *string `json:"id" validate:"required"`

	// [REQUIRED] The PolicyName (or PolicyID if the name doesn't exist) of the triggered alert.
	Name *string `json:"name" validate:"required"`

	// [REQUIRED] The severity of the alert
	Severity *string `json:"severity" validate:"required,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// [REQUIRED] Type specifies if an alert is for a policy or a rule
	Type *string `json:"type" validate:"required,oneof=RULE POLICY UNKNOWN"`

	// [REQUIRED] Link to the alert in Panther UI
	Link *string `json:"link" validate:"required"`

	// [REQUIRED] A human readable title of the alert
	Title *string `json:"title" validate:"required"`

	// [REQUIRED] A human readable description of the rule that triggered the alert
	Description *string `json:"description"`

	// Runbook is the user-provided triage information
	Runbook *string `json:"runbook"`

	// Tags is the set of policy tags
	Tags []*string `json:"tags"`

	// Version is the S3 object version for the policy
	Version *string `json:"version"`
}

//CustomWebhookOutputMessage contains the fields that will be included in the Custom Webhook message
type CustomWebhookOutputMessage struct {
	// Alert contains the details of the alert
	Alert CustomWebhookAlert `json:"alert" validate:"required"`

	// CreatedAt is the timestamp (seconds since epoch) of the alert at creation.
	CreatedAt *time.Time `json:"createdAt" validate:"required"`
}
