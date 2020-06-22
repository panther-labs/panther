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

var githubConfig = &outputmodels.GithubConfig{RepoName: "profile/reponame", Token: "github-token"}

func TestGithubAlert(t *testing.T) {
	httpWrapper := &mockHTTPWrapper{}
	client := &OutputClient{httpWrapper: httpWrapper}

	var createdAtTime, _ = time.Parse(time.RFC3339, "2019-08-03T11:40:13Z")
	alert := &alertmodels.Alert{
		AnalysisID:          "ruleId",
		CreatedAt:           createdAtTime,
		OutputIDs:           []string{"output-id"},
		AnalysisDescription: aws.String("description"),
		AnalysisName:        aws.String("rule_name"),
		Severity:            "INFO",
	}

	githubRequest := map[string]interface{}{
		"title": "Policy Failure: rule_name",
		"body": "**Description:** description\n " +
			"[Click here to view in the Panther UI](https://panther.io/policies/ruleId)\n" +
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

	httpWrapper.On("post", expectedPostInput).Return((*AlertDeliveryError)(nil))

	require.Nil(t, client.Github(alert, githubConfig))
	httpWrapper.AssertExpectations(t)
}
