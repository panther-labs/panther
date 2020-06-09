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
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// CustomWebhook alert send an alert.
func (client *OutputClient) CustomWebhook(
	alert *alertmodels.Alert, config *outputmodels.CustomWebhookConfig) *AlertDeliveryError {

	// Get a link to the Panther Dashboard to one of the following:
	//   1. The PolicyID (if no AlertID is present)
	//   2. The AlertID
	link := generateURL(alert)

	outputMessage := &CustomWebhookOutputMessage{
		AnalysisID:  alert.PolicyID,
		AlertID:     alert.AlertID,
		Name:        alert.PolicyName,
		Severity:    alert.Severity,
		Type:        alert.Type,
		Link:        &link,
		Title:       alert.Title,
		Description: alert.PolicyDescription,
		Runbook:     alert.Runbook,
		Tags:        alert.Tags,
		Version:     alert.PolicyVersionID,
		CreatedAt:   alert.CreatedAt,
	}

	// Ensure we have slices instead of `null` array fields
	gatewayapi.ReplaceMapSliceNils(outputMessage)

	requestURL := *config.WebhookURL
	postInput := &PostInput{
		url: requestURL,
		body: map[string]interface{}{
			"alert": outputMessage,
		},
	}
	return client.httpWrapper.post(postInput)
}

// CustomWebhookOutputMessage describes the details of an alert in a Custom Webhook message
//
// This struct should never use the `omitempty` attribute as we want to keep the keys even
// if they have `null` fields. However, we need to ensure there are no `null` arrays or
// objects.
type CustomWebhookOutputMessage struct {
	// [REQUIRED] The PolicyID
	AnalysisID *string `json:"analysisId" validate:"required"`

	// An AlertID that was triggered by a Rule (or in the future, a Policy)
	AlertID *string `json:"alertId"`

	// The Name of the triggered alert set in Panther UI
	Name *string `json:"name"`

	// [REQUIRED] The severity enum of the alert set in Panther UI
	Severity *string `json:"severity" validate:"required,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// [REQUIRED] The Type enum if an alert is for a rule or policy
	Type *string `json:"type" validate:"required,oneof=RULE POLICY"`

	// Link to the alert in Panther UI
	Link *string `json:"link"`

	// The dynamic Title set from a user-configurable python rule in Panther UI
	Title *string `json:"title"`

	// The Description of the rule set in Panther UI
	Description *string `json:"description"`

	// The Runbook is the user-provided triage information set in Panther UI
	Runbook *string `json:"runbook"`

	// Tags is the set of policy tags set in Panther UI
	Tags []*string `json:"tags"`

	// Version is the S3 object version for the policy
	Version *string `json:"version"`

	// [REQUIRED] CreatedAt is the timestamp (RFC3339) of the alert at creation.
	CreatedAt *time.Time `json:"createdAt" validate:"required"`
}
