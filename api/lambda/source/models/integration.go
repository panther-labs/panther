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

	"github.com/panther-labs/panther/internal/compliance/snapshotlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
)

// SourceIntegration represents a Panther integration with a source.
type SourceIntegration struct {
	SourceIntegrationMetadata
	SourceIntegrationStatus
	SourceIntegrationScanInformation
}

// SourceIntegrationStatus provides information about the status of a source
type SourceIntegrationStatus struct {
	ScanStatus        string     `json:"scanStatus,omitempty"`
	EventStatus       string     `json:"eventStatus,omitempty"`
	LastEventReceived *time.Time `json:"lastEventReceived,omitempty"`
}

// SourceIntegrationScanInformation is detail about the last snapshot.
type SourceIntegrationScanInformation struct {
	LastScanStartTime    *time.Time `json:"lastScanStartTime,omitempty"`
	LastScanEndTime      *time.Time `json:"lastScanEndTime,omitempty"`
	LastScanErrorMessage string     `json:"lastScanErrorMessage,omitempty"`
}

// SourceIntegrationMetadata is general settings and metadata for an integration.
type SourceIntegrationMetadata struct {
	AWSAccountID       string     `json:"awsAccountId,omitempty"`
	CreatedAtTime      time.Time  `json:"createdAtTime,omitempty"`
	CreatedBy          string     `json:"createdBy,omitempty"`
	IntegrationID      string     `json:"integrationId,omitempty"`
	IntegrationLabel   string     `json:"integrationLabel,omitempty"`
	IntegrationType    string     `json:"integrationType,omitempty"`
	RemediationEnabled *bool      `json:"remediationEnabled,omitempty"`
	CWEEnabled         *bool      `json:"cweEnabled,omitempty"`
	ScanIntervalMins   int        `json:"scanIntervalMins,omitempty"`
	S3Bucket           string     `json:"s3Bucket,omitempty"`
	S3Prefix           string     `json:"s3Prefix,omitempty"`
	KmsKey             string     `json:"kmsKey,omitempty"`
	LogTypes           []string   `json:"logTypes,omitempty"`
	LogProcessingRole  string     `json:"logProcessingRole,omitempty"`
	StackName          string     `json:"stackName,omitempty"`
	SqsConfig          *SqsConfig `json:"sqsConfig,omitempty"`
}

func (s *SourceIntegration) RequiredLogTypes() (logTypes []string) {
	switch typ := s.IntegrationType; typ {
	case IntegrationTypeAWS3:
		return s.LogTypes
	case IntegrationTypeAWSScan:
		return logtypes.CollectNames(snapshotlogs.LogTypes())
	case IntegrationTypeSqs:
		return s.SqsConfig.LogTypes
	default:
		panic("Unknown type " + typ)
	}
}

func (s *SourceIntegration) RequiredLogProcessingRole() string {
	switch typ := s.IntegrationType; typ {
	case IntegrationTypeAWS3, IntegrationTypeAWSScan:
		return s.LogProcessingRole
	case IntegrationTypeSqs:
		return s.SqsConfig.LogProcessingRole
	default:
		panic("Unknown type " + typ)
	}
}

func (s *SourceIntegration) RequiredS3Prefix() string {
	switch typ := s.IntegrationType; typ {
	case IntegrationTypeAWS3:
		return s.S3Prefix
	case IntegrationTypeAWSScan:
		return "cloudsecurity"
	case IntegrationTypeSqs:
		return "forwarder"
	default:
		panic("Unknown type " + typ)
	}
}

func (s *SourceIntegration) RequiredS3Bucket() string {
	switch typ := s.IntegrationType; typ {
	case IntegrationTypeAWS3, IntegrationTypeAWSScan:
		return s.S3Bucket
	case IntegrationTypeSqs:
		return s.SqsConfig.S3Bucket
	default:
		panic("Unknown type " + typ)
	}
}

type SourceIntegrationHealth struct {
	IntegrationType string `json:"integrationType"`

	// Checks for cloudsec integrations
	AuditRoleStatus       SourceIntegrationItemStatus `json:"auditRoleStatus,omitempty"`
	CWERoleStatus         SourceIntegrationItemStatus `json:"cweRoleStatus,omitempty"`
	RemediationRoleStatus SourceIntegrationItemStatus `json:"remediationRoleStatus,omitempty"`

	// Checks for log analysis integrations
	ProcessingRoleStatus SourceIntegrationItemStatus `json:"processingRoleStatus,omitempty"`
	S3BucketStatus       SourceIntegrationItemStatus `json:"s3BucketStatus,omitempty"`
	KMSKeyStatus         SourceIntegrationItemStatus `json:"kmsKeyStatus,omitempty"`

	// Checks for Sqs integrations
	SqsStatus SourceIntegrationItemStatus `json:"sqsStatus"`
}

type SourceIntegrationItemStatus struct {
	Healthy      bool   `json:"healthy"`
	Message      string `json:"message"`
	ErrorMessage string `json:"rawErrorMessage,omitempty"`
}

type SourceIntegrationTemplate struct {
	Body      string `json:"body"`
	StackName string `json:"stackName"`
}

type SqsConfig struct {
	// The log types associated with the source. Needs to be set by UI.
	LogTypes []string `json:"logTypes" validate:"required,min=1"`
	// The AWS Principals that are allowed to send data to this source. Needs to be set by UI.
	AllowedPrincipalArns []string `json:"allowedPrincipalArns"`
	// The ARNS (e.g. SNS topic ARNs) that are allowed to send data to this source. Needs to be set by UI.
	AllowedSourceArns []string `json:"allowedSourceArns"`

	// The Panther-internal S3 bucket where the data from this source will be available
	S3Bucket string `json:"s3Bucket"`
	// The Role that the log processor can use to access this data
	LogProcessingRole string `json:"logProcessingRole"`
	// THe URL of the SQS queue
	QueueURL string `json:"queueUrl"`
}
