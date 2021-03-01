package models

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

// LambdaInput is the invocation event expected by the Lambda function.
//
// Exactly one action must be specified.
type LambdaInput struct {
	AddOutput             *AddOutputInput             `json:"addOutput"`
	UpdateOutput          *UpdateOutputInput          `json:"updateOutput"`
	GetOutput             *GetOutputInput             `json:"getOutput"`
	DeleteOutput          *DeleteOutputInput          `json:"deleteOutput"`
	GetOutputs            *GetOutputsInput            `json:"getOutputs"`
	GetOutputsWithSecrets *GetOutputsWithSecretsInput `json:"getOutputsWithSecrets"`
}

// AddOutputInput adds a new encrypted alert output to DynamoDB.
//
// Example:
// {
//     "addOutput": {
//         "displayName": "alert-channel",
//         "userId": "f6cfad0a-9bb0-4681-9503-02c54cc979c7",
//         "slack": {
//             "webhookURL": "https://hooks.slack.com/services/..."
//         }
//     }
// }
type AddOutputInput struct {
	UserID             *string       `json:"userId" validate:"required,uuid4"`
	DisplayName        *string       `json:"displayName" validate:"required,min=1,excludesall='<>&\""`
	OutputConfig       *OutputConfig `json:"outputConfig" validate:"required"`
	DefaultForSeverity []*string     `json:"defaultForSeverity"`
	AlertTypes         []string      `json:"alertTypes" validate:"omitempty,dive,oneof=RULE RULE_ERROR POLICY"`
}

// AddOutputOutput returns a randomly generated UUID for the output.
//
// Example:
// {
//     "displayName": "alert-channel",
//     "outputId": "7d1c5854-f3ea-491c-8a52-0aa0d58cb456",
//     "outputType": "slack",
//	   "alertTypes": ["RULE", "RULE_ERROR", "POLICY"],
// }
type AddOutputOutput = AlertOutput

// DeleteOutputInput permanently deletes output credentials.
//
// Example:
// {
//     "deleteOutput": {
//         "outputId": "7d1c5854-f3ea-491c-8a52-0aa0d58cb456"
//     }
// }
type DeleteOutputInput struct {
	OutputID *string `json:"outputId" validate:"required,uuid4"`
}

// UpdateOutputInput updates an alert output configuration.
//
// Example:
// {
//     "updateOutput": {
//         "userId": "9d1c5854-f3ea-491c-8a52-0aa0d58cb456",
//         "outputId": "7d1c5854-f3ea-491c-8a52-0aa0d58cb456",
//	       "alertTypes": ["RULE", "RULE_ERROR", "POLICY"]
//     }
// }
type UpdateOutputInput struct {
	UserID             *string       `json:"userId" validate:"required,uuid4"`
	DisplayName        *string       `json:"displayName" validate:"omitempty,min=1,excludesall='<>&\""`
	OutputID           *string       `json:"outputId" validate:"required,uuid4"`
	OutputConfig       *OutputConfig `json:"outputConfig"`
	DefaultForSeverity []*string     `json:"defaultForSeverity"`
	AlertTypes         []string      `json:"alertTypes" validate:"omitempty,dive,oneof=RULE RULE_ERROR POLICY"`
}

// UpdateOutputOutput returns the new updated output
//
// Example:
// {
//     "displayName": "alert-channel",
//     "outputId": "7d1c5854-f3ea-491c-8a52-0aa0d58cb456",
//     "outputType": "slack"
// }
type UpdateOutputOutput = AlertOutput

// GetOutputInput fetches the configuration for a specific alert output id of an organization
type GetOutputInput struct {
	OutputID *string `json:"outputId" validate:"required,uuid4"`
}

// GetOutputOutput contains the configuration for an alert
type GetOutputOutput = AlertOutput

// GetOutputsInput fetches all alert output configuration for one organization
//
// Example:
// {
//     "getOutputs": {
//     }
// }
type GetOutputsInput struct {
}

// GetOutputsWithSecretsInput fetches all alert output configuration for one organization
// without redacting their secrets
type GetOutputsWithSecretsInput struct {
}

// GetOutputsOutput returns all the alert outputs for one organization
//
// Example:
// {
//     "displayName": "alert-channel",
//     "outputId": "7d1c5854-f3ea-491c-8a52-0aa0d58cb456",
//     "outputType": "slack"
// }
type GetOutputsOutput = []*AlertOutput

// AlertOutput contains the information for alert output configuration
type AlertOutput struct {
	// AlertTypes is a whitelist of alert types to send to this destination.
	// To be backwards compatible, we cannot have a `min=1` and an empty list == all types.
	AlertTypes []string `json:"alertTypes" validate:"omitempty,dive,oneof=RULE RULE_ERROR POLICY"`

	// The user ID of the user that created the alert output
	CreatedBy *string `json:"createdBy"`

	// The time when the alert output was created
	CreationTime *string `json:"creationTime"`

	// DisplayName is the user-provided name, e.g. "alert-channel".
	DisplayName *string `json:"displayName"`

	// The user ID of the user that last modified the alert output last
	LastModifiedBy *string `json:"lastModifiedBy"`

	// The time when the alert output was last modified
	LastModifiedTime *string `json:"lastModifiedTime"`

	// Identifies uniquely an alert output (table sort key)
	OutputID *string `json:"outputId"`

	// OutputType is the output class, e.g. "slack", "sns".
	// ("type" is a reserved Dynamo keyword, so we use "OutputType" instead)
	OutputType *string `json:"outputType"`

	// OutputConfig contains the configuration for this output
	OutputConfig *OutputConfig `json:"outputConfig"`

	// DefaultForSeverity defines the alert severities that will be forwarded through this output
	DefaultForSeverity []*string `json:"defaultForSeverity"`
}

// OutputConfig contains the configuration for the output
type OutputConfig struct {
	// SlackConfig contains the configuration for Slack alert output
	Slack *SlackConfig `json:"slack,omitempty"`

	// SnsConfig contains the configuration for SNS alert output
	Sns *SnsConfig `json:"sns,omitempty"`

	// PagerDuty contains the configuration for PagerDuty alert output
	PagerDuty *PagerDutyConfig `json:"pagerDuty,omitempty"`

	// Github contains the configuration for Github alert output
	Github *GithubConfig `json:"github,omitempty"`

	// Jira contains the configuration for Jira alert output
	Jira *JiraConfig `json:"jira,omitempty"`

	// Opsgenie contains the configuration for Opsgenie alert output
	Opsgenie *OpsgenieConfig `json:"opsgenie,omitempty"`

	// MsTeams contains the configuration for MsTeams alert output
	MsTeams *MsTeamsConfig `json:"msTeams,omitempty"`

	// SqsConfig contains the configuration for SQS alert output
	Sqs *SqsConfig `json:"sqs,omitempty"`

	// AsanaConfig contains the configuration for Asana alert output
	Asana *AsanaConfig `json:"asana,omitempty"`

	// CustomWebhook contains the configuration for a Custom Webhook alert output
	CustomWebhook *CustomWebhookConfig `json:"customWebhook,omitempty"`
}

// SlackConfig defines options for each Slack output.
type SlackConfig struct {
	WebhookURL string `json:"webhookURL" validate:"omitempty,url"` // https://hooks.slack.com/services/...
}

// SnsConfig defines options for each SNS topic output
type SnsConfig struct {
	TopicArn string `json:"topicArn" validate:"omitempty,snsArn"`
}

// PagerDutyConfig defines options for each PagerDuty output
type PagerDutyConfig struct {
	IntegrationKey string `json:"integrationKey" validate:"omitempty,hexadecimal,len=32"`
}

// GithubConfig defines options for each Github output
type GithubConfig struct {
	RepoName string `json:"repoName"`
	Token    string `json:"token"`
}

// JiraConfig defines options for each Jira output
type JiraConfig struct {
	OrgDomain  string   `json:"orgDomain" validate:"url"`
	ProjectKey string   `json:"projectKey" validate:"required"`
	UserName   string   `json:"userName" validate:"required"`
	APIKey     string   `json:"apiKey"`
	AssigneeID string   `json:"assigneeId"`
	Type       string   `json:"issueType"`
	Labels     []string `json:"labels" validate:"required,dive,min=1"`
}

// OpsgenieConfig defines options for each Opsgenie output
type OpsgenieConfig struct {
	APIKey        string `json:"apiKey"`
	ServiceRegion string `json:"serviceRegion" validate:"oneof=US EU"`
}

// MsTeamsConfig defines options for each MsTeams output
type MsTeamsConfig struct {
	WebhookURL string `json:"webhookURL" validate:"omitempty,url"`
}

// SqsConfig defines options for each Sqs topic output
type SqsConfig struct {
	QueueURL string `json:"queueUrl" validate:"omitempty,url"`
}

// AsanaConfig defines options for each Asana output
type AsanaConfig struct {
	PersonalAccessToken string   `json:"personalAccessToken" validate:"omitempty,min=1"`
	ProjectGids         []string `json:"projectGids" validate:"omitempty,min=1,dive,required"`
}

// CustomWebhookConfig defines options for each CustomWebhook output
type CustomWebhookConfig struct {
	WebhookURL string `json:"webhookURL" validate:"omitempty,url"`
}
