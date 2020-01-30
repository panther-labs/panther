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

	var tagsItem = aws.StringValueSlice(alert.Tags)

	description := "*Description:* " + aws.StringValue(alert.PolicyDescription)
	link := "\n [Click here to view in the Panther UI](" + generateURL(alert) + ")"
	runBook := "\n *Runbook:* " + aws.StringValue(alert.Runbook)
	severity := "\n *Severity:* " + aws.StringValue(alert.Severity)
	tags := "\n *Tags:* " + strings.Join(tagsItem, ", ")

	fields := map[string]interface{}{
		"summary":     generateAlertTitle(alert),
		"description": description + link + runBook + severity + tags,
		"project": map[string]*string{
			"key": config.ProjectKey,
		},
		"issuetype": map[string]*string{
			"name": config.Type,
		},
	}

	if aws.StringValue(config.AssigneeID) != "" {
		fields["assignee"] = map[string]*string{
			"id": config.AssigneeID,
		}
	}

	jiraRequest := map[string]interface{}{
		"fields": fields,
	}

	auth := *config.UserName + ":" + *config.APIKey
	basicAuthToken := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	accept := "application/json"
	jiraRestURL := *config.OrgDomain + jiraEndpoint
	requestHeader := map[string]*string{
		"Accept":        &accept,
		"Authorization": &basicAuthToken,
	}

	postInput := &PostInput{
		url:     &jiraRestURL,
		body:    jiraRequest,
		headers: requestHeader,
	}
	return client.httpWrapper.post(postInput)
}
