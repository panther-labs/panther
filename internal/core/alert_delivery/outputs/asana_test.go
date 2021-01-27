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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

func TestAsanaAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	createdAtTime, err := time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	require.NoError(t, err)
	alert := &deliverymodel.Alert{
		AlertID:             aws.String("alertId"),
		AnalysisID:          "ruleId",
		Type:                deliverymodel.PolicyType,
		CreatedAt:           createdAtTime,
		OutputIds:           []string{"output-id"},
		AnalysisDescription: "description",
		AnalysisName:        aws.String("policy_name"),
		Severity:            "INFO",
		Context:             map[string]interface{}{"key": "value"},
	}

	asanaConfig := &outputModels.AsanaConfig{PersonalAccessToken: "token", ProjectGids: []string{"projectGid"}}

	asanaRequest := map[string]interface{}{
		"data": map[string]interface{}{
			"name": "Policy Failure: policy_name",
			"notes": "policy_name failed on new resources\n" +
				"For more details please visit: https://panther.io/alerts/alertId\nSeverity: INFO\nRunbook: \n" +
				"Reference: \nDescription: description\nAlertContext: {\"key\":\"value\"}",
			"projects": []string{"projectGid"},
		},
	}

	authorization := "Bearer " + asanaConfig.PersonalAccessToken
	requestHeader := map[string]string{
		AuthorizationHTTPHeader: authorization,
	}
	expectedPostInput := &PostInput{
		url:     asanaCreateTaskURL,
		body:    asanaRequest,
		headers: requestHeader,
	}
	ctx := context.Background()
	httpWrapper.On("post", ctx, expectedPostInput).Return((*AlertDeliveryResponse)(nil))

	assert.Nil(t, client.Asana(ctx, alert, asanaConfig))
	httpWrapper.AssertExpectations(t)
}
