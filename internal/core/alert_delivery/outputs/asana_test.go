package outputs

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

func TestAsanaAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	createdAtTime, err := time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	require.NoError(t, err)
	alert := &alertmodels.Alert{
		PolicyID:          aws.String("ruleId"),
		CreatedAt:         &createdAtTime,
		OutputIDs:         aws.StringSlice([]string{"output-id"}),
		PolicyDescription: aws.String("description"),
		PolicyName:        aws.String("policy_name"),
		Severity:          aws.String("INFO"),
	}

	asanaConfig := &outputmodels.AsanaConfig{PersonalAccessToken: aws.String("token"), ProjectGids: aws.StringSlice([]string{"projectGid"})}

	asanaRequest := map[string]interface{}{
		"data": map[string]interface{}{
			"name":     "Policy Failure: policy_name",
			"notes":    "policy_name failed on new resources\nFor more details please visit: https://panther.io/policies/ruleId\nSeverity: INFO\nRunbook: \nDescription:description",
			"projects": aws.StringSlice([]string{"projectGid"}),
		},
	}

	authorization := "Bearer " + *asanaConfig.PersonalAccessToken
	requestHeader := map[string]string{
		AuthorizationHTTPHeader: authorization,
	}
	expectedPostInput := &PostInput{
		url:     asanaCreateTaskURL,
		body:    asanaRequest,
		headers: requestHeader,
	}

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryError)(nil))

	require.Nil(t, client.Asana(alert, asanaConfig))
	httpWrapper.AssertExpectations(t)
}
