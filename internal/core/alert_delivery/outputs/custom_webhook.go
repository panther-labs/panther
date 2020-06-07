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

	version := "1.0.0"
	link := policyURLPrefix + aws.StringValue(alert.PolicyID)

	outputMessage := &CustomWebhookOutputMessage{
		PolicyID:          alert.PolicyID,
		PolicyName:        alert.PolicyName,
		PolicyDescription: alert.PolicyDescription,
		PolicyVersionID:   alert.PolicyVersionID,
		AlertID:           alert.AlertID,
		Title:             alert.Title,
		Type:              alert.Type,
		Severity:          alert.Severity,
		Tags:              alert.Tags,
		Runbook:           alert.Runbook,
		Link:              &link,
		Version:           &version,
		CreatedAt:         alert.CreatedAt,
	}

	requestURL := *config.WebhookURL
	postInput := &PostInput{
		url: requestURL,
		body: map[string]interface{}{
			"payload": outputMessage,
			"version": outputMessage.Version,
		},
	}
	return client.httpWrapper.post(postInput)
}

//CustomWebhookOutputMessage contains the fields that will be included in the Custom Webhook message
type CustomWebhookOutputMessage struct {
	// PolicyID is the rule that triggered the alert.
	PolicyID *string `json:"policyId" validate:"required"`

	// PolicyName is the name of the policy at the time the alert was triggered.
	PolicyName *string `json:"policyName,omitempty"`

	// PolicyDescription is the description of the rule that triggered the alert.
	PolicyDescription *string `json:"policyDescription,omitempty"`

	// PolicyVersionID is the S3 object version for the policy.
	PolicyVersionID *string `json:"policyVersionId,omitempty"`

	// AlertID specifies the alertId that this Alert is associated with.
	AlertID *string `json:"alertId,omitempty"`

	// Title is the optional title for the alert
	Title *string `json:"title,omitempty"`

	// Type specifies if an alert is for a policy or a rule
	Type *string `json:"type,omitempty" validate:"omitempty,oneof=RULE POLICY"`

	// Severity is the alert severity at the time of creation.
	Severity *string `json:"severity" validate:"required,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Tags is the set of policy tags.
	Tags []*string `json:"tags,omitempty"`

	// Runbook is the user-provided triage information.
	Runbook *string `json:"runbook,omitempty"`

	// Link to the alert in Panther UI
	Link *string `json:"link" validate:"required"`

	// A version string associated to this type.
	Version *string `json:"version" validate:"required"`

	// CreatedAt is the creation timestamp (seconds since epoch).
	CreatedAt *time.Time `json:"createdAt" validate:"required"`
}
