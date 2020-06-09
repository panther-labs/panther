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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var customWebhookConfig = &outputmodels.CustomWebhookConfig{
	WebhookURL: aws.String("custom-webhook-url"),
}

func TestCustomWebhookAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	// Define the required fields for an alert
	// The custom webhook should be able to produce the correct
	// output from a bare bones alert
	createdAtTime, err := time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	if err != nil {
		t.Error(err)
	}
	alert := &alertmodels.Alert{
		PolicyID:  aws.String("policyId"),
		CreatedAt: &createdAtTime,
		Severity:  aws.String("INFO"),
	}

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

	requestURL := *customWebhookConfig.WebhookURL

	expectedPostInput := &PostInput{
		url: requestURL,
		body: map[string]interface{}{
			"alert": outputMessage,
		},
	}

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryError)(nil))

	require.Nil(t, client.CustomWebhook(alert, customWebhookConfig))
	httpWrapper.AssertExpectations(t)
}
