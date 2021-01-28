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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

var slackConfig = &outputModels.SlackConfig{WebhookURL: "slack-channel-url"}

func TestSlackAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	createdAtTime := time.Now()
	alert := &deliverymodel.Alert{
		AlertID:      aws.String("alertId"),
		AnalysisID:   "policyId",
		Type:         deliverymodel.PolicyType,
		CreatedAt:    createdAtTime,
		OutputIds:    []string{"output-id"},
		AnalysisName: aws.String("policyName"),
		Severity:     "INFO",
	}

	expectedPostPayload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{"color": "#47b881",
				"fallback": "Policy Failure: policyName",
				"fields": []map[string]interface{}{
					{
						"short": false,
						"value": "<https://panther.io/alerts/alertId|Click here to view in the Panther UI>",
					},
					{
						"short": false,
						"title": "Runbook",
						"value": "",
					},
					{
						"short": true,
						"title": "Severity",
						"value": "INFO",
					},
				},
				"title": "Policy Failure: policyName",
			},
		},
	}
	requestURL := slackConfig.WebhookURL
	expectedPostInput := &PostInput{
		url:  requestURL,
		body: expectedPostPayload,
	}

	ctx := context.Background()
	httpWrapper.On("post", ctx, expectedPostInput).Return((*AlertDeliveryResponse)(nil))

	require.Nil(t, client.Slack(ctx, alert, slackConfig))
	httpWrapper.AssertExpectations(t)
}
