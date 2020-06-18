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
	CreatedAtTime    *time.Time `json:"createdAtTime"`
	CreatedBy        *string    `json:"createdBy"`
	IntegrationID    *string    `json:"integrationId"`
	IntegrationLabel *string    `json:"integrationLabel"`
	IntegrationType  *string    `json:"integrationType"`

	AWSAccountID       *string `json:"awsAccountId"`
	RemediationEnabled *bool   `json:"remediationEnabled"`
	CWEEnabled         *bool   `json:"cweEnabled"`

	LastScanEndTime      *time.Time `json:"lastScanEndTime"`
	LastScanErrorMessage *string    `json:"lastScanErrorMessage"`
	LastScanStartTime    *time.Time `json:"lastScanStartTime"`
	ScanIntervalMins     *int       `json:"scanIntervalMins"`
	IntegrationStatus

	S3Bucket          *string   `json:"s3Bucket"`
	S3Prefix          *string   `json:"s3Prefix"`
	KmsKey            *string   `json:"kmsKey"`
	LogTypes          []*string `json:"logTypes" dynamodbav:"logTypes,stringset"`
	StackName         *string   `json:"stackName,omitempty"`
	LogProcessingRole *string   `json:"logProcessingRole,omitempty"`
}

type IntegrationStatus struct {
	ScanStatus        *string   `json:"scanStatus"`
	EventStatus       *string   `json:"eventStatus"`
	LastEventReceived time.Time `json:"lastEventReceived"`
}
