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
	"encoding/base64"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

var jiraConfig = &outputModels.JiraConfig{
	APIKey:     "apikey",
	AssigneeID: "ae393k930390",
	OrgDomain:  "https://panther-labs.atlassian.net",
	ProjectKey: "QR",
	Type:       "Task",
	UserName:   "username",
	Labels:     []string{"panther", "test-label"},
}

func TestJiraAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	var createdAtTime, _ = time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	alert := &deliverymodel.Alert{
		AlertID:             aws.String("alertId"),
		AnalysisID:          "policyId",
		Type:                deliverymodel.PolicyType,
		CreatedAt:           createdAtTime,
		OutputIds:           []string{"output-id"},
		AnalysisDescription: "policyDescription",
		Severity:            "INFO",
		Context:             map[string]interface{}{"key": "value"},
	}
	jiraPayload := map[string]interface{}{
		"fields": map[string]interface{}{
			"summary": "Policy Failure: policyId",
			"description": "*Description:* policyDescription\n " +
				"[Click here to view in the Panther UI|https://panther.io/alerts/alertId]\n" +
				" *Runbook:* \n *Severity:* INFO\n *Tags:* \n *AlertContext:* {\"key\":\"value\"}",
			"project": map[string]*string{
				"key": aws.String(jiraConfig.ProjectKey),
			},
			"issuetype": map[string]*string{
				"name": aws.String(jiraConfig.Type),
			},
			"assignee": map[string]*string{
				"id": aws.String(jiraConfig.AssigneeID),
			},
			"labels": aws.StringSlice(jiraConfig.Labels),
		},
	}
	auth := jiraConfig.UserName + ":" + jiraConfig.APIKey
	basicAuthToken := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	requestHeader := map[string]string{
		AuthorizationHTTPHeader: basicAuthToken,
	}
	requestEndpoint := "https://panther-labs.atlassian.net/rest/api/latest/issue/"
	expectedPostInput := &PostInput{
		url:     requestEndpoint,
		body:    jiraPayload,
		headers: requestHeader,
	}
	ctx := context.Background()
	httpWrapper.On("post", ctx, expectedPostInput).Return((*AlertDeliveryResponse)(nil))

	assert.Nil(t, client.Jira(ctx, alert, jiraConfig))
	httpWrapper.AssertExpectations(t)
}
