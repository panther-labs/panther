package models

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

// LambdaInput is the invocation event expected by the Lambda function.
//
// Exactly one action must be specified.
type LambdaInput struct {
	AddOutput    *AddOutputInput    `json:"addOutput"`
	UpdateOutput *UpdateOutputInput `json:"updateOutput"`
	GetOutput    *GetOutputInput    `json:"getOutput"`
	DeleteOutput *DeleteOutputInput `json:"deleteOutput"`
	GetOutputs   *GetOutputsInput   `json:"getOutputs"`
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
	DisplayName        *string       `json:"displayName" validate:"required,min=1"`
	OutputConfig       *OutputConfig `json:"outputConfig" validate:"required"`
	DefaultForSeverity []*string     `json:"defaultForSeverity"`
}

// AddOutputOutput returns a randomly generated UUID for the output.
//
// Example:
// {
//     "displayName": "alert-channel",
//     "outputId": "7d1c5854-f3ea-491c-8a52-0aa0d58cb456",
//     "outputType": "slack"
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
//         "outputId": "7d1c5854-f3ea-491c-8a52-0aa0d58cb456"
//     }
// }
type UpdateOutputInput struct {
	UserID             *string       `json:"userId" validate:"required,uuid4"`
	DisplayName        *string       `json:"displayName" validate:"required,min=1"`
	OutputID           *string       `json:"outputId" validate:"required,uuid4"`
	OutputConfig       *OutputConfig `json:"outputConfig" validate:"required"`
	DefaultForSeverity []*string     `json:"defaultForSeverity"`
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

// GetOrganizationOutputsInput fetches all alert output configuration for one organization
//
// Example:
// {
//     "getOutputs": {
//     }
// }
type GetOutputsInput struct {
}

// GetOrganizationOutputsOutput returns all the alert outputs for one organization
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

	// The user ID of the user that created the alert output
	CreatedBy *string `json:"createdBy"`

	// The time in epoch seconds when the alert output was created
	CreationTime *string `json:"creationTime"`

	// DisplayName is the user-provided name, e.g. "alert-channel".
	DisplayName *string `json:"displayName"`

	// The user ID of the user that last modified the alert output last
	LastModifiedBy *string `json:"lastModifiedBy"`

	// The time in epoch seconds when the alert output was last modified
	LastModifiedTime *string `json:"lastModifiedTime"`

	// Identifies uniquely an alert output (table sort key)
	OutputID *string `json:"outputId"`

	// OutputType is the output class, e.g. "slack", "sns".
	// ("type" is a reserved Dynamo keyword, so we use "OutputType" instead)
	OutputType *string `json:"outputType"`

	// OutputConfig contains the configuration for this output
	OutputConfig *OutputConfig `json:"outputConfig"`

	// VerificationStatus is the current state of the output verification process.
	VerificationStatus *string `json:"verificationStatus"`

	// DefaultForSeverity defines the alert severities that will be forwarded through this output
	DefaultForSeverity []*string `json:"defaultForSeverity"`
}

const (
	// VerificationStatusNotStarted shows that the verification process hasn't started yet
	VerificationStatusNotStarted = "NOT_STARTED"

	// VerificationStatusPending shows that a verification is pending
	VerificationStatusPending = "PENDING"

	// VerificationStatusFailed shows that the verification process has failed
	VerificationStatusFailed = "FAILED"

	// VerificationStatusSuccess shows that a verification is successful
	VerificationStatusSuccess = "SUCCESS"
)

// OutputConfig contains the configuration for the output
type OutputConfig struct {
	// SlackConfig contains the configuration for Slack alert output
	Slack *SlackConfig `json:"slack,omitempty"`

	// SnsConfig contains the configuration for SNS alert output
	Sns *SnsConfig `json:"sns,omitempty"`

	// SnsConfig contains the configuration for Email alert output
	Email *EmailConfig `json:"email,omitempty"`

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
}

// SlackConfig defines options for each Slack output.
type SlackConfig struct {
	WebhookURL *string `json:"webhookURL" validate:"required,url"` // https://hooks.slack.com/services/...
}

// SnsConfig defines options for each SNS topic output
type SnsConfig struct {
	TopicArn *string `json:"topicArn" validate:"required,snsArn"`
}

// PagerDutyConfig defines options for each PagerDuty output
type PagerDutyConfig struct {
	IntegrationKey *string `json:"integrationKey" validate:"required,hexadecimal,len=32"`
}

// EmailConfig defines options for each Email output
type EmailConfig struct {
	DestinationAddress *string `json:"destinationAddress" validate:"required"`
}

// GithubConfig defines options for each Github output
type GithubConfig struct {
	RepoName *string `json:"repoName" validate:"required"`
	Token    *string `json:"token" validate:"required"`
}

// JiraConfig defines options for each Jira output
type JiraConfig struct {
	OrgDomain  *string `json:"orgDomain" validate:"required"`
	ProjectKey *string `json:"projectKey" validate:"required"`
	UserName   *string `json:"userName" validate:"required"`
	APIKey     *string `json:"apiKey" validate:"required"`
	AssigneeID *string `json:"assigneeId"`
	Type       *string `json:"issueType"`
}

// OpsgenieConfig defines options for each Opsgenie output
type OpsgenieConfig struct {
	APIKey *string `json:"apiKey" validate:"required"`
}

// MsTeamsConfig defines options for each MsTeamsConfig output
type MsTeamsConfig struct {
	WebhookURL *string `json:"webhookURL" validate:"required,url"`
}

// SqsConfig defines options for each Sqs topic output
type SqsConfig struct {
	QueueURL *string `json:"queueUrl" validate:"required,url"`
}

// DefaultOutputs is the structure holding the information about default outputs for severity
type DefaultOutputs struct {
	Severity  *string   `json:"severity"`
	OutputIDs []*string `json:"outputIds"`
}
