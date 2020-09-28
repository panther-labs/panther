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

	alertModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

var githubConfig = &outputModels.GithubConfig{RepoName: "profile/reponame", Token: "github-token"}

func TestGithubAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	var createdAtTime, _ = time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	alert := &alertModels.Alert{
		AnalysisID:          "policyId",
		Type:                alertModels.PolicyType,
		CreatedAt:           createdAtTime,
		OutputIds:           []string{"output-id"},
		AnalysisDescription: aws.String("description"),
		AnalysisName:        aws.String("policy_name"),
		Severity:            "INFO",
	}

	githubRequest := map[string]interface{}{
		"title": "Policy Failure: policy_name",
		"body": "**Description:** description\n " +
			"[Click here to view in the Panther UI](https://panther.io/policies/policyId)\n" +
			" **Runbook:** \n **Severity:** INFO\n **Tags:** ",
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

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryResponse)(nil))

	require.Nil(t, client.Github(alert, githubConfig))
	httpWrapper.AssertExpectations(t)
}
