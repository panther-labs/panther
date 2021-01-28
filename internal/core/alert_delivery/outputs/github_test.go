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

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

var githubConfig = &outputModels.GithubConfig{RepoName: "profile/reponame", Token: "github-token"}

func TestGithubAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	var createdAtTime, _ = time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	alert := &deliverymodel.Alert{
		AlertID:             aws.String("alertId"),
		AnalysisID:          "policyId",
		Type:                deliverymodel.PolicyType,
		CreatedAt:           createdAtTime,
		OutputIds:           []string{"output-id"},
		AnalysisDescription: "description",
		AnalysisName:        aws.String("policy_name"),
		Severity:            "INFO",
		Context:             map[string]interface{}{"key": "value"},
	}

	githubRequest := map[string]interface{}{
		"title": "Policy Failure: policy_name",
		"body": "**Description:** description\n " +
			"[Click here to view in the Panther UI](https://panther.io/alerts/alertId)\n" +
			" **Runbook:** \n **Severity:** INFO\n **Tags:** \n **AlertContext:** {\"key\":\"value\"}",
	}

	authorization := "token " + githubConfig.Token
	requestHeader := map[string]string{
		AuthorizationHTTPHeader: authorization,
	}
	requestEndpoint := "https://api.github.com/repos/profile/reponame/issues"
	expectedPostInput := &PostInput{
		url:     requestEndpoint,
		body:    githubRequest,
		headers: requestHeader,
	}
	ctx := context.Background()
	httpWrapper.On("post", ctx, expectedPostInput).Return((*AlertDeliveryResponse)(nil))

	assert.Nil(t, client.Github(ctx, alert, githubConfig))
	httpWrapper.AssertExpectations(t)
}
