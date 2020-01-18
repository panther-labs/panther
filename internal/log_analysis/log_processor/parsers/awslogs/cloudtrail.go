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
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var CloudTrailDesc = `AWSCloudTrail represents the content of a CloudTrail S3 object.
Log format & samples can be seen here: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html`

type CloudTrailRecords struct {
	Records []*CloudTrail `json:"Records" validate:"required"`
}

// CloudTrailRecord is an AWS CloudTrail API log.
type CloudTrail struct {
	AdditionalEventData interface{}             `json:"additionalEventData,omitempty"`
	APIVersion          *string                 `json:"apiVersion,omitempty" validate:"required"`
	AWSRegion           *string                 `json:"awsRegion,omitempty" validate:"required"`
	ErrorCode           *string                 `json:"errorCode,omitempty"`
	ErrorMessage        *string                 `json:"errorMessage,omitempty"`
	EventID             *string                 `json:"eventId,omitempty" validate:"required"`
	EventName           *string                 `json:"eventName,omitempty"`
	EventSource         *string                 `json:"eventSource,omitempty"`
	EventTime           *timestamp.RFC3339      `json:"eventTime,omitempty"`
	EventType           *string                 `json:"eventType,omitempty"`
	EventVersion        *string                 `json:"eventVersion,omitempty" validate:"required"`
	ManagementEvent     *bool                   `json:"managementEvent,omitempty"`
	ReadOnly            *bool                   `json:"readOnly,omitempty"`
	RecipientAccountID  *string                 `json:"recipientAccountId,omitempty" validate:"required,len=12,numeric"`
	RequestID           *string                 `json:"requestId,omitempty"`
	RequestParameters   interface{}             `json:"requestParameters,omitempty"`
	Resources           []CloudTrailResources   `json:"resources,omitempty"`
	ResponseElements    interface{}             `json:"responseElements,omitempty"`
	ServiceEventDetails interface{}             `json:"serviceEventDetails,omitempty"`
	SharedEventID       *string                 `json:"sharedEventId,omitempty"`
	SourceIPAddress     *string                 `json:"sourceIpAddress,omitempty"`
	UserAgent           *string                 `json:"userAgent,omitempty"`
	UserIdentity        *CloudTrailUserIdentity `json:"userIdentity,omitempty"`
	VPCEndpointID       *string                 `json:"vpcEndpointId,omitempty"`
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
	FederatedProvider *string     `json:"federatedProvider,omitempty"`
	Attributes        interface{} `json:"attributes,omitempty"`
}

// CloudTrailParser parses CloudTrail logs
type CloudTrailParser struct{}

// Parse returns the parsed events or nil if parsing failed
func (p *CloudTrailParser) Parse(log string) []interface{} {
	cloudTrailRecords := &CloudTrailRecords{}
	err := jsoniter.UnmarshalFromString(log, cloudTrailRecords)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
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
