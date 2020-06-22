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

var msTeamConfig = &outputmodels.MsTeamsConfig{
	WebhookURL: "msteam-url",
}

func TestMsTeamsAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	var createdAtTime, _ = time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	alert := &alertmodels.Alert{
		AnalysisID:   "policyId",
		CreatedAt:    createdAtTime,
		OutputIDs:    []string{"output-id"},
		AnalysisName: aws.String("policyName"),
		Severity:     "INFO",
	}

	msTeamsPayload := map[string]interface{}{
		"@context": "http://schema.org/extensions",
		"@type":    "MessageCard",
		"text":     "Policy Failure: policyName",
		"sections": []interface{}{
			map[string]interface{}{
				"facts": []interface{}{
					map[string]string{"name": "Description", "value": ""},
					map[string]string{"name": "Runbook", "value": ""},
					map[string]string{"name": "Severity", "value": "INFO"},
					map[string]string{"name": "Tags", "value": ""},
				},
				"text": "[Click here to view in the Panther UI](https://panther.io/policies/policyId).\n",
			},
		},
		"potentialAction": []interface{}{
			map[string]interface{}{
				"@type": "OpenUri",
				"name":  "Click here to view in the Panther UI",
				"targets": []interface{}{
					map[string]string{
						"os":  "default",
						"uri": "https://panther.io/policies/policyId",
					},
				},
			},
		},
	}

	requestURL := msTeamConfig.WebhookURL

	expectedPostInput := &PostInput{
		url:  requestURL,
		body: msTeamsPayload,
	}

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryError)(nil))

	require.Nil(t, client.MsTeams(alert, msTeamConfig))
	httpWrapper.AssertExpectations(t)
}
