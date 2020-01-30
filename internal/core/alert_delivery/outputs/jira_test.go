package outputs

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

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

var jiraConfig = &outputmodels.JiraConfig{
	APIKey:     aws.String("apikey"),
	AssigneeID: aws.String("ae393k930390"),
	OrgDomain:  aws.String("https://panther-labs.atlassian.net"),
	ProjectKey: aws.String("QR"),
	Type:       aws.String("Task"),
	UserName:   aws.String("username"),
}

func TestJiraAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	var createdAtTime, _ = time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	alert := &alertmodels.Alert{
		PolicyID:          aws.String("ruleId"),
		CreatedAt:         &createdAtTime,
		OutputIDs:         aws.StringSlice([]string{"output-id"}),
		PolicyDescription: aws.String("policyDescription"),
		Severity:          aws.String("INFO"),
	}

	jiraPayload := map[string]interface{}{
		"fields": map[string]interface{}{
			"summary": "Policy Failure: ruleId",
			"description": "*Description:* policyDescription\n " +
				"[Click here to view in the Panther UI](https://panther.io/policies/ruleId)\n" +
				" *Runbook:* \n *Severity:* INFO\n *Tags:* ",
			"project": map[string]*string{
				"key": jiraConfig.ProjectKey,
			},
			"issuetype": map[string]*string{
				"name": jiraConfig.Type,
			},
			"assignee": map[string]*string{
				"id": jiraConfig.AssigneeID,
			},
		},
	}
	auth := *jiraConfig.UserName + ":" + *jiraConfig.APIKey
	basicAuthToken := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	accept := "application/json"
	requestHeader := map[string]*string{
		"Authorization": &basicAuthToken,
		"Accept":        &accept,
	}
	requestEndpoint := "https://panther-labs.atlassian.net/rest/api/latest/issue/"
	expectedPostInput := &PostInput{
		url:     &requestEndpoint,
		body:    jiraPayload,
		headers: requestHeader,
	}

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryError)(nil))

	require.Nil(t, client.Jira(alert, jiraConfig))
	httpWrapper.AssertExpectations(t)
}
