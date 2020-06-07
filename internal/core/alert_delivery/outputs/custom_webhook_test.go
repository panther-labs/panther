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
)

var customWebhookConfig = &outputmodels.CustomWebhookConfig{
	WebhookURL: aws.String("custom-webhook-url"),
}

func TestCustomWebhookAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	var createdAtTime, _ = time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	alert := &alertmodels.Alert{
		PolicyID:   aws.String("policyId"),
		CreatedAt:  &createdAtTime,
		OutputIDs:  aws.StringSlice([]string{"output-id"}),
		PolicyName: aws.String("policyName"),
		Severity:   aws.String("INFO"),
	}

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

	requestURL := *customWebhookConfig.WebhookURL

	expectedPostInput := &PostInput{
		url: requestURL,
		body: map[string]interface{}{
			"payload": outputMessage,
			"version": outputMessage.Version,
		},
	}

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryError)(nil))

	require.Nil(t, client.CustomWebhook(alert, customWebhookConfig))
	httpWrapper.AssertExpectations(t)
}
