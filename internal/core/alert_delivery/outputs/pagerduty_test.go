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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	alertModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

var (
	createdAtTime, _ = time.Parse(time.RFC3339, "2019-05-03T11:40:13Z")
	pagerDutyAlert   = &alertModels.Alert{
		AnalysisName: aws.String("policyName"),
		AnalysisID:   "policyId",
		Severity:     "INFO",
		Runbook:      "runbook",
		CreatedAt:    createdAtTime,
		Type:         alertModels.PolicyType,
	}
	pagerDutyConfig = &outputModels.PagerDutyConfig{
		IntegrationKey: "integrationKey",
	}
)

func TestSendPagerDutyAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	outputClient := &OutputClient{httpWrapper: httpWrapper}

	expectedPostPayload := map[string]interface{}{
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"custom_details": Notification{
				ID:           "policyId",
				CreatedAt:    createdAtTime,
				Severity:     "INFO",
				Type:         alertModels.PolicyType,
				Link:         "https://panther.io/policies/policyId",
				Title:        "Policy Failure: policyName",
				Name:         aws.String("policyName"),
				Description:  aws.String(""),
				Runbook:      aws.String("runbook"),
				Tags:         []string{},
				AlertContext: make(map[string]interface{}),
			},
			"severity":  "info",
			"source":    "pantherlabs",
			"summary":   "Policy Failure: policyName",
			"timestamp": "2019-05-03T11:40:13Z",
		},
		"routing_key": "integrationKey",
	}
	requestEndpoint := "https://events.pagerduty.com/v2/enqueue"
	expectedPostInput := &PostInput{
		url:  requestEndpoint,
		body: expectedPostPayload,
	}

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryResponse)(nil))
	result := outputClient.PagerDuty(pagerDutyAlert, pagerDutyConfig)

	assert.Nil(t, result)
	httpWrapper.AssertExpectations(t)
}

func TestSendPagerDutyAlertPostError(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	outputClient := &OutputClient{httpWrapper: httpWrapper}

	httpWrapper.On("post", mock.Anything).Return(&AlertDeliveryResponse{Message: "Exception"})

	require.Error(t, outputClient.PagerDuty(pagerDutyAlert, pagerDutyConfig))
	httpWrapper.AssertExpectations(t)
}
