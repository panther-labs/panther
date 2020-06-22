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
	"encoding/base64"
	"strings"

	"github.com/aws/aws-sdk-go/aws"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

const (
	jiraEndpoint = "/rest/api/latest/issue/"
)

// Jira alert send an issue.
func (client *OutputClient) Jira(
	alert *alertmodels.Alert, config *outputmodels.JiraConfig) *AlertDeliveryError {

	description := "*Description:* " + aws.StringValue(alert.AnalysisDescription)
	link := "\n [Click here to view in the Panther UI](" + generateURL(alert) + ")"
	runBook := "\n *Runbook:* " + aws.StringValue(alert.Runbook)
	severity := "\n *Severity:* " + alert.Severity
	tags := "\n *Tags:* " + strings.Join(alert.Tags, ", ")

	fields := map[string]interface{}{
		"summary":     generateAlertTitle(alert),
		"description": description + link + runBook + severity + tags,
		"project": map[string]*string{
			"key": aws.String(config.ProjectKey),
		},
		"issuetype": map[string]*string{
			"name": aws.String(config.Type),
		},
	}

	if config.AssigneeID != "" {
		fields["assignee"] = map[string]*string{
			"id": aws.String(config.AssigneeID),
		}
	}

	jiraRequest := map[string]interface{}{
		"fields": fields,
	}

	auth := config.UserName + ":" + config.APIKey
	basicAuthToken := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	jiraRestURL := config.OrgDomain + jiraEndpoint
	requestHeader := map[string]string{
		AuthorizationHTTPHeader: basicAuthToken,
	}

	postInput := &PostInput{
		url:     jiraRestURL,
		body:    jiraRequest,
		headers: requestHeader,
	}
	return client.httpWrapper.post(postInput)
}
