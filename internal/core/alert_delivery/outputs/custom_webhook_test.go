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

	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

var customWebhookConfig = &outputmodels.CustomWebhookConfig{
	WebhookURL: "custom-webhook-url",
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
		AnalysisID: "policyId",
		CreatedAt:  createdAtTime,
		Severity:   "INFO",
	}

	expectedNotification := Notification{
		AnalysisID:   alert.AnalysisID,
		AlertID:      alert.AlertID,
		AnalysisName: alert.AnalysisName,
		Severity:     alert.Severity,
		Type:         alert.Type,
		Link:         "https://panther.io/policies/policyId",
		Title:        "Policy Failure: policyId",
		Description:  alert.AnalysisDescription,
		Runbook:      alert.Runbook,
		Tags:         []string{},
		Version:      alert.Version,
		CreatedAt:    alert.CreatedAt,
	}

	expectedPostInput := &PostInput{
		url:  "custom-webhook-url",
		body: expectedNotification,
	}

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryError)(nil))

	require.Nil(t, client.CustomWebhook(alert, customWebhookConfig))
	httpWrapper.AssertExpectations(t)
}
