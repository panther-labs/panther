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

import (
	"time"

	"github.com/aws/aws-lambda-go/events"

	alertModels "github.com/panther-labs/panther/api/lambda/alerts/models"
)

const (
	// RuleType identifies the Alert to be for a Rule
	RuleType = "RULE"

	// RuleErrorType identifies the Alert to be for a Rule error
	RuleErrorType = "RULE_ERROR"

	// PolicyType identifies the Alert to be for a Policy
	PolicyType = "POLICY"
)

// LambdaInput is the invocation event expected by the Lambda function.
//
// Exactly one action must be specified, see comments below for examples.
type LambdaInput struct {
	// `DispatchAlerts` is an alias for `SQSMessage` so that we can invoke directly
	// in AWS UI with a valid `SQSMessage` JSON payload without needing to put data on
	// the queue and wait for the trigger. This matches the raw SQS message format
	// (hence 'Records' being the name of the field), but genericapi will route the
	// request to the DispatchAlerts handler. This way all requests can be routed
	// by genericapi without having to inspect the message ahead of time.
	DispatchAlerts []*DispatchAlertsInput `json:"Records"`
	DeliverAlert   *DeliverAlertInput     `json:"deliverAlert"`
	SendTestAlert  *SendTestAlertInput    `json:"sendTestAlert"`
}

// SendTestAlertInput sends a dummy alert to the specified destinations
//
// Example:
// {
//     "sendTestAlert": {
//         "outputIds": ["198bdbc5-5d94-4d59-8c93-f2bab86359f5"]
//     }
// }
type SendTestAlertInput struct {
	OutputIds []string `json:"outputIds" validate:"gt=0,dive,uuid4"`
}

// SendTestAlertOutput holds only the attributes we want to return to the user
type SendTestAlertOutput struct {
	OutputID     string    `json:"outputId"`
	Message      string    `json:"message"`
	StatusCode   int       `json:"statusCode"`
	Success      bool      `json:"success"`
	DispatchedAt time.Time `json:"dispatchedAt"`
}

// DeliverAlertInput sends an alert to the specified destinations
//
// Example:
// {
//     "deliverAlert": {
//         "alertId": "8304cc90750d4b8f9a63b90a4543c707"
//         "outputIds": ["198bdbc5-5d94-4d59-8c93-f2bab86359f5"]
//     }
// }
type DeliverAlertInput struct {
	AlertID   string   `json:"alertId" validate:"required,hexadecimal,len=32"` // AlertID is an MD5 hash
	OutputIds []string `json:"outputIds" validate:"gt=0,dive,uuid4"`
}

// DispatchAlertsInput is an alias for an SQSMessage
//
// Example:
// {
// 	"Records": [
// 	  {
// 		"MessageId": "messageId",
// 		"ReceiptHandle": "MessageReceiptHandle",
// 		"Body": "{\"analysisId\":\"Test.Analysis.ID\",\"type\":\"RULE\", 		\
//        \"createdAt\":\"2020-09-01T21:10:41.80307Z\",\"severity\":\"INFO\", 	\
//        \"outputIds\":[\"1954ae35-f896-4d55-941f-f596ea80da86\",				\
//        \"d498bac4-7ec3-432c-92b5-9a470d592c16\"],\"analysisDescription\":	\
//        \"A test alert\",\"analysisName\":\"Test Analysis Name\",\"version\":	\
//        \"abc\",\"runbook\":\"A runbook link\",\"tags\":[\"test\",\"alert\"],	\
//        \"alertId\":\"1302cc3f4fab40b37f6f6a441e944206\",\"title\":\"Test Alert\"}",
// 		"Md5OfBody": "7b270e59b47ff90a553787216d55d91d",
// 		"Attributes": {
// 		  "ApproximateReceiveCount": "1",
// 		  "SentTimestamp": "1523232000000",
// 		  "SenderId": "123456789012",
// 		  "ApproximateFirstReceiveTimestamp": "1523232000001"
// 		},
// 		"EventSourceARN": "arn:aws:sqs:us-west-2:123456789012:MyQueue",
// 		"EventSource": "aws:sqs",
// 		"AWSRegion": "us-west-2"
// 	  }
// 	]
// }
type DispatchAlertsInput = events.SQSMessage

// DeliverAlertOutput is an alias for an alert summary
type DeliverAlertOutput = alertModels.AlertSummary

// Alert is the schema for each row in the Dynamo alerts table.
type Alert struct {
	// ID is the rule/policy that triggered the alert.
	AnalysisID string `json:"analysisId" validate:"required"`

	// Type specifies if an alert is for a policy or a rule
	Type string `json:"type" validate:"oneof=RULE POLICY RULE_ERROR"`

	// CreatedAt is the creation timestamp (seconds since epoch).
	CreatedAt time.Time `json:"createdAt" validate:"required"`

	// Severity is the alert severity at the time of creation.
	Severity string `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// OutputIds is the set of outputs for this alert.
	OutputIds []string `json:"outputIds,omitempty" validate:"dive,uuid4"`

	// LogTypes is the set of logs that could trigger the alert.
	LogTypes []string `json:"logTypes,omitempty"`

	// ResourceTypes is the set of resources that could trigger the alert.
	ResourceTypes []string `json:"resourceTypes,omitempty"`

	// ResourceID is the ID of the failing resource in the policy.
	ResourceID string `json:"resourceId,omitempty"`

	// AnalysisSourceID is the ID of the source integration for the rule/policy that failed.
	AnalysisSourceID string `json:"analysisSourceId,omitempty"`

	// AnalysisDescription is the description of the rule/policy that triggered the alert.
	AnalysisDescription string `json:"analysisDescription,omitempty"`

	// Name is the name of the policy at the time the alert was triggered.
	AnalysisName *string `json:"analysisName,omitempty"`

	// Version is the S3 object version for the policy.
	Version *string `json:"version,omitempty"`

	// Reference is the user-provided triage information
	Reference string `json:"reference,omitempty"`

	// Destinations is the custom user-provided destination override
	Destinations []string `json:"destinations,omitempty" validate:"dive,uuid4"`

	// Runbook is the user-provided triage information.
	Runbook string `json:"runbook,omitempty"`

	// Tags is the set of policy tags.
	Tags []string `json:"tags,omitempty"`

	// AlertID specifies the alertId that this Alert is associated with.
	AlertID *string `json:"alertId,omitempty"`

	// Title is the optional title for the alert generated by Python Rules engine
	Title string `json:"title,omitempty"`

	Context map[string]interface{} `json:"context"`

	// RetryCount is a counter for the nubmer of times we have attempted to send this alert to a destination.
	RetryCount int `json:"retryCount,omitempty"`

	// IsTest is a test flag set only to replace the contents of the alert with dummy values
	IsTest bool `json:"isTest,omitempty"`

	// IsResent is a flag set to indicate the alert is not new
	IsResent bool `json:"isResent,omitempty"`
}
