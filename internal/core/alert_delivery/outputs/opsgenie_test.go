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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

var opsgenieConfig = &outputModels.OpsgenieConfig{APIKey: "apikey", ServiceRegion: OpsgenieServiceRegionUS}

func TestOpsgenieAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	createdAtTime, err := time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	require.NoError(t, err)
	alert := &deliverymodel.Alert{
		AlertID:      aws.String("alertId"),
		AnalysisID:   "policyId",
		Type:         deliverymodel.PolicyType,
		CreatedAt:    createdAtTime,
		OutputIds:    []string{"output-id"},
		AnalysisName: aws.String("policyName"),
		Severity:     "CRITICAL",
		Tags:         []string{"tag"},
		Context:      map[string]interface{}{"key": "value"},
	}

	opsgenieRequest := map[string]interface{}{
		"message": "Policy Failure: policyName",
		"description": strings.Join([]string{
			"<strong>Description:</strong> ",
			"<a href=\"https://panther.io/alerts/alertId\">Click here to view in the Panther UI</a>",
			" <strong>Runbook:</strong> ",
			" <strong>Severity:</strong> CRITICAL",
			" <strong>AlertContext:</strong> {\"key\":\"value\"}",
		}, "\n"),
		"tags":     []string{"tag"},
		"priority": "P1",
	}

	authorization := "GenieKey " + opsgenieConfig.APIKey

	requestHeader := map[string]string{
		AuthorizationHTTPHeader: authorization,
	}

	requestEndpoint := GetOpsGenieRegionalEndpoint(opsgenieConfig.ServiceRegion)

	expectedPostInput := &PostInput{
		url:     requestEndpoint,
		body:    opsgenieRequest,
		headers: requestHeader,
	}
	ctx := context.Background()
	httpWrapper.On("post", ctx, expectedPostInput).Return((*AlertDeliveryResponse)(nil))

	assert.Nil(t, client.Opsgenie(ctx, alert, opsgenieConfig))
	httpWrapper.AssertExpectations(t)
}

func TestOpsgenieServiceRegion(t *testing.T) {
	opsGenieRegions := []string{"", OpsgenieServiceRegionUS, OpsgenieServiceRegionEU}
	//nolint:lll
	expectedEndpoints := []string{"https://api.opsgenie.com/v2/alerts", "https://api.opsgenie.com/v2/alerts", "https://api.eu.opsgenie.com/v2/alerts"}
	for i, serviceRegion := range opsGenieRegions {
		assert.Equal(t, expectedEndpoints[i], GetOpsGenieRegionalEndpoint(serviceRegion))
	}
}
