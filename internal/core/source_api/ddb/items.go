package ddb

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

import "time"

// Integration represents an integration item as it is stored in DynamoDB.
type Integration struct {
	CreatedAtTime    time.Time `json:"createdAtTime,omitempty"`
	CreatedBy        string    `json:"createdBy,omitempty"`
	IntegrationID    string    `json:"integrationId,omitempty"`
	IntegrationLabel string    `json:"integrationLabel,omitempty"`
	IntegrationType  string    `json:"integrationType,omitempty"`

	AWSAccountID       string `json:"awsAccountId,omitempty"`
	RemediationEnabled *bool  `json:"remediationEnabled,omitempty"`
	CWEEnabled         *bool  `json:"cweEnabled,omitempty"`

	LastScanStartTime    *time.Time `json:"lastScanStartTime,omitempty"`
	LastScanEndTime      *time.Time `json:"lastScanEndTime,omitempty"`
	LastScanErrorMessage string     `json:"lastScanErrorMessage,omitempty"`
	ScanIntervalMins     int        `json:"scanIntervalMins,omitempty"`
	IntegrationStatus

	S3Bucket          string   `json:"s3Bucket,omitempty"`
	S3Prefix          string   `json:"s3Prefix,omitempty"`
	KmsKey            string   `json:"kmsKey,omitempty"`
	LogTypes          []string `json:"logTypes,omitempty" dynamodbav:",stringset"`
	StackName         string   `json:"stackName,omitempty"`
	LogProcessingRole string   `json:"logProcessingRole,omitempty"`

	SqsConfig *SqsConfig `json:"sqsConfig,omitempty"`
}

type IntegrationStatus struct {
	ScanStatus        string     `json:"scanStatus,omitempty"`
	EventStatus       string     `json:"eventStatus,omitempty"`
	LastEventReceived *time.Time `json:"lastEventReceived,omitempty"`
}

type SqsConfig struct {
	S3Bucket          string   `json:"s3Bucket,omitempty"`
	S3Prefix          string   `json:"s3Prefix,omitempty"`
	LogProcessingRole string   `json:"logProcessingRole,omitempty"`
	LogTypes          []string `json:"logTypes" dynamodbav:",stringset"`
	AllowedPrincipals []string `json:"allowedPrincipals" dynamodbav:",stringset"`
	AllowedSourceArns []string `json:"allowedSourceArns" dynamodbav:",stringset"`
	QueueURL          string   `json:"queueUrl,omitempty"`
}
