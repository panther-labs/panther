package awslogs

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
	"strings"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/extract"
)

var CloudTrailDesc = `AWSCloudTrail represents the content of a CloudTrail S3 object.
Log format & samples can be seen here: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html`

type CloudTrailRecords struct {
	Records []*CloudTrail `json:"Records" validate:"required,dive"`
}

// CloudTrail is a record from the Records[*] JSON of an AWS CloudTrail API log.
// nolint:lll
type CloudTrail struct {
	AdditionalEventData *jsoniter.RawMessage    `json:"additionalEventData,omitempty" description:"Additional data about the event that was not part of the request or response."`
	APIVersion          *string                 `json:"apiVersion,omitempty" description:"Identifies the API version associated with the AwsApiCall eventType value."`
	AWSRegion           *string                 `json:"awsRegion,omitempty" validate:"required" description:"The AWS region that the request was made to, such as us-east-2."`
	ErrorCode           *string                 `json:"errorCode,omitempty" description:"The AWS service error if the request returns an error."`
	ErrorMessage        *string                 `json:"errorMessage,omitempty" description:"If the request returns an error, the description of the error. This message includes messages for authorization failures. CloudTrail captures the message logged by the service in its exception handling."`
	EventID             *string                 `json:"eventId,omitempty" validate:"required" description:"GUID generated by CloudTrail to uniquely identify each event. You can use this value to identify a single event. For example, you can use the ID as a primary key to retrieve log data from a searchable database."`
	EventName           *string                 `json:"eventName,omitempty" validate:"required" description:"The requested action, which is one of the actions in the API for that service."`
	EventSource         *string                 `json:"eventSource,omitempty" validate:"required" description:"The service that the request was made to. This name is typically a short form of the service name without spaces plus .amazonaws.com."`
	EventTime           *timestamp.RFC3339      `json:"eventTime,omitempty" validate:"required" description:"The date and time the request was made, in coordinated universal time (UTC)."`
	EventType           *string                 `json:"eventType,omitempty" validate:"required" description:"Identifies the type of event that generated the event record. This can be the one of the following values: AwsApiCall, AwsServiceEvent, AwsConsoleSignIn"`
	EventVersion        *string                 `json:"eventVersion,omitempty" validate:"required" description:"The version of the log event format."`
	ManagementEvent     *bool                   `json:"managementEvent,omitempty" description:"A Boolean value that identifies whether the event is a management event. managementEvent is shown in an event record if eventVersion is 1.06 or higher, and the event type is one of the following: AwsApiCall, AwsConsoleAction, AwsConsoleSignIn,  AwsServiceEvent"`
	ReadOnly            *bool                   `json:"readOnly,omitempty" description:"Identifies whether this operation is a read-only operation."`
	RecipientAccountID  *string                 `json:"recipientAccountId,omitempty" validate:"omitempty,len=12,numeric" description:"Represents the account ID that received this event. The recipientAccountID may be different from the CloudTrail userIdentity Element accountId. This can occur in cross-account resource access."`
	RequestID           *string                 `json:"requestId,omitempty" description:"The value that identifies the request. The service being called generates this value."`
	RequestParameters   *jsoniter.RawMessage    `json:"requestParameters,omitempty" description:"The parameters, if any, that were sent with the request. These parameters are documented in the API reference documentation for the appropriate AWS service."`
	Resources           []CloudTrailResources   `json:"resources,omitempty" description:"A list of resources accessed in the event."`
	ResponseElements    *jsoniter.RawMessage    `json:"responseElements,omitempty" description:"The response element for actions that make changes (create, update, or delete actions). If an action does not change state (for example, a request to get or list objects), this element is omitted. These actions are documented in the API reference documentation for the appropriate AWS service."`
	ServiceEventDetails *jsoniter.RawMessage    `json:"serviceEventDetails,omitempty" description:"Identifies the service event, including what triggered the event and the result."`
	SharedEventID       *string                 `json:"sharedEventId,omitempty" description:"GUID generated by CloudTrail to uniquely identify CloudTrail events from the same AWS action that is sent to different AWS accounts."`
	SourceIPAddress     *string                 `json:"sourceIpAddress,omitempty" validate:"required" description:"The IP address that the request was made from. For actions that originate from the service console, the address reported is for the underlying customer resource, not the console web server. For services in AWS, only the DNS name is displayed."`
	UserAgent           *string                 `json:"userAgent,omitempty" description:"The agent through which the request was made, such as the AWS Management Console, an AWS service, the AWS SDKs or the AWS CLI."`
	UserIdentity        *CloudTrailUserIdentity `json:"userIdentity,omitempty" validate:"required" description:"Information about the user that made a request."`
	VPCEndpointID       *string                 `json:"vpcEndpointId,omitempty" description:"Identifies the VPC endpoint in which requests were made from a VPC to another AWS service, such as Amazon S3."`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// CloudTrailResources are the AWS resources used in the API call.
type CloudTrailResources struct {
	ARN       *string `json:"arn"`
	AccountID *string `json:"accountId"`
	Type      *string `json:"type"`
}

// CloudTrailUserIdentity contains details about the type of IAM identity that made the request.
type CloudTrailUserIdentity struct {
	Type             *string                   `json:"type,omitempty"`
	PrincipalID      *string                   `json:"principalId,omitempty"`
	ARN              *string                   `json:"arn,omitempty"`
	AccountID        *string                   `json:"accountId,omitempty"`
	AccessKeyID      *string                   `json:"accessKeyId,omitempty"`
	Username         *string                   `json:"userName,omitempty"`
	SessionContext   *CloudTrailSessionContext `json:"sessionContext,omitempty"`
	InvokedBy        *string                   `json:"invokedBy,omitempty"`
	IdentityProvider *string                   `json:"identityProvider,omitempty"`
}

// CloudTrailSessionContext provides information about a session created for temporary credentials.
type CloudTrailSessionContext struct {
	Attributes          *CloudTrailSessionContextAttributes          `json:"attributes,omitempty"`
	SessionIssuer       *CloudTrailSessionContextSessionIssuer       `json:"sessionIssuer,omitempty"`
	WebIDFederationData *CloudTrailSessionContextWebIDFederationData `json:"webIdFederationData,omitempty"`
}

// CloudTrailSessionContextAttributes  contains the attributes of the Session context object
type CloudTrailSessionContextAttributes struct {
	MfaAuthenticated *string `json:"mfaAuthenticated,omitempty"`
	CreationDate     *string `json:"creationDate,omitempty"`
}

// CloudTrailSessionContextSessionIssuer contains information for the SessionContextSessionIssuer
type CloudTrailSessionContextSessionIssuer struct {
	Type        *string `json:"type,omitempty"`
	PrincipalID *string `json:"principalId,omitempty"`
	Arn         *string `json:"arn,omitempty"`
	AccountID   *string `json:"accountId,omitempty"`
	Username    *string `json:"userName,omitempty"`
}

// CloudTrailSessionContextWebIDFederationData contains Web ID federation data
type CloudTrailSessionContextWebIDFederationData struct {
	FederatedProvider *string              `json:"federatedProvider,omitempty"`
	Attributes        *jsoniter.RawMessage `json:"attributes,omitempty"`
}

// CloudTrailParser parses CloudTrail logs
type CloudTrailParser struct{}

func (p *CloudTrailParser) New() parsers.LogParser {
	return &CloudTrailParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *CloudTrailParser) Parse(log string) []interface{} {
	cloudTrailRecords := &CloudTrailRecords{}
	err := jsoniter.UnmarshalFromString(log, cloudTrailRecords)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	for _, event := range cloudTrailRecords.Records {
		event.updatePantherFields(p)
	}

	if err := parsers.Validator.Struct(cloudTrailRecords); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}
	result := make([]interface{}, len(cloudTrailRecords.Records))
	for i, record := range cloudTrailRecords.Records {
		result[i] = record
	}
	return result
}

// LogType returns the log type supported by this parser
func (p *CloudTrailParser) LogType() string {
	return "AWS.CloudTrail"
}

func (event *CloudTrail) updatePantherFields(p *CloudTrailParser) {
	event.SetCoreFields(p.LogType(), event.EventTime)

	// structured (parsed) fields
	if event.SourceIPAddress != nil && !strings.HasSuffix(*event.SourceIPAddress, "amazonaws.com") {
		event.AppendAnyIPAddresses(*event.SourceIPAddress)
	}

	for _, resource := range event.Resources {
		event.AppendAnyAWSARNPtrs(resource.ARN)
		event.AppendAnyAWSAccountIdPtrs(resource.AccountID)
	}
	if event.UserIdentity != nil {
		event.AppendAnyAWSAccountIdPtrs(event.UserIdentity.AccountID)
		event.AppendAnyAWSARNPtrs(event.UserIdentity.ARN)

		if event.UserIdentity.SessionContext != nil {
			if event.UserIdentity.SessionContext.SessionIssuer != nil {
				event.AppendAnyAWSAccountIdPtrs(event.UserIdentity.SessionContext.SessionIssuer.AccountID)
				event.AppendAnyAWSARNPtrs(event.UserIdentity.SessionContext.SessionIssuer.Arn)
			}
		}
	}

	// polymorphic (unparsed) fields
	awsExtractor := NewAWSExtractor(&(event.AWSPantherLog))
	extract.Extract(event.AdditionalEventData, awsExtractor)
	extract.Extract(event.RequestParameters, awsExtractor)
	extract.Extract(event.ResponseElements, awsExtractor)
	extract.Extract(event.ServiceEventDetails, awsExtractor)
	if event.UserIdentity.SessionContext != nil && event.UserIdentity.SessionContext.WebIDFederationData != nil {
		extract.Extract(event.UserIdentity.SessionContext.WebIDFederationData.Attributes, awsExtractor)
	}
}
