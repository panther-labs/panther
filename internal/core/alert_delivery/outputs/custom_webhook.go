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

	"github.com/aws/aws-sdk-go/aws"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

// CustomWebhook alert send an alert.
func (client *OutputClient) CustomWebhook(
	alert *alertmodels.Alert, config *outputmodels.CustomWebhookConfig) *AlertDeliveryError {

	link := policyURLPrefix + aws.StringValue(alert.PolicyID)

	customWebhookPolicy := &CustomWebhookPolicy{
		ID:          alert.PolicyID,
		Name:        alert.PolicyName,
		Description: alert.PolicyDescription,
		Version:     alert.PolicyVersionID,
		Tags:        alert.Tags,
	}

	customWebhookAlert := &CustomWebhookAlert{
		ID:       alert.AlertID,
		Title:    alert.Title,
		Type:     alert.Type,
		Severity: alert.Severity,
		Runbook:  alert.Runbook,
		Link:     &link,
		Policy:   *customWebhookPolicy,
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

//CustomWebhookPolicy is the internal struct describing the alert policy in the Custom Webhook message
type CustomWebhookPolicy struct {
	// ID is the rule that triggered the alert.
	ID *string `json:"id" validate:"required"`

	// The name of the policy at the time the alert was triggered.
	Name *string `json:"name,omitempty"`

	// Description is the description of the rule that triggered the alert.
	Description *string `json:"description,omitempty"`

	// Version is the S3 object version for the policy.
	Version *string `json:"versionId,omitempty"`

	// Tags is the set of policy tags.
	Tags []*string `json:"tags,omitempty"`
}

//CustomWebhookAlert is the internal struct describing an alert in the Custom Webhook message
type CustomWebhookAlert struct {
	// ID specifies the alertId that this Alert is associated with.
	ID *string `json:"id,omitempty"`

	// Title is the optional title for the alert
	Title *string `json:"title,omitempty"`

	// Type specifies if an alert is for a policy or a rule
	Type *string `json:"type,omitempty" validate:"omitempty,oneof=RULE POLICY"`

	// Severity is the alert severity at the time of creation.
	Severity *string `json:"severity" validate:"required,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Runbook is the user-provided triage information.
	Runbook *string `json:"runbook,omitempty"`

	// Link to the alert in Panther UI
	Link *string `json:"link" validate:"required"`

	// Policy contains the policy details associated with the alert
	Policy CustomWebhookPolicy
}

//CustomWebhookOutputMessage contains the fields that will be included in the Custom Webhook message
type CustomWebhookOutputMessage struct {
	// Alert contains the details of the alert
	Alert CustomWebhookAlert

	// CreatedAt is the creation timestamp (seconds since epoch).
	CreatedAt *time.Time `json:"createdAt" validate:"required"`
}
