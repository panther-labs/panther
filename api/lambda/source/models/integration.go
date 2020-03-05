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

import "time"

// SourceIntegration is the dynamodb item corresponding to the PutIntegration route.
type SourceIntegration struct {
	*SourceIntegrationMetadata
	*SourceIntegrationStatus
	*SourceIntegrationScanInformation
}

// SourceIntegrationMetadata is general settings and metadata for an integration.
type SourceIntegrationMetadata struct {
	AWSAccountID     *string    `json:"awsAccountId"`
	CreatedAtTime    *time.Time `json:"createdAtTime"`
	CreatedBy        *string    `json:"createdBy"`
	IntegrationID    *string    `json:"integrationId"`
	IntegrationLabel *string    `json:"integrationLabel"`
	IntegrationType  *string    `json:"integrationType"`
	ScanEnabled      *bool      `json:"scanEnabled"`
	ScanIntervalMins *int       `json:"scanIntervalMins"`
	S3Buckets        []*string  `json:"s3Buckets"`
	KmsKeys          []*string  `json:"kmsKeys"`
}

// SourceIntegrationStatus provides context that the full scan works and that events are being received.
type SourceIntegrationStatus struct {
	ScanStatus  *string `json:"scanStatus"`
	EventStatus *string `json:"eventStatus"`
}

// SourceIntegrationScanInformation is detail about the last snapshot.
type SourceIntegrationScanInformation struct {
	LastScanEndTime      *time.Time `json:"lastScanEndTime"`
	LastScanErrorMessage *string    `json:"lastScanErrorMessage"`
	LastScanStartTime    *time.Time `json:"lastScanStartTime"`
}

type SourceIntegrationHealth struct {
	AWSAccountID    *string `json:"awsAccountId"`
	IntegrationType *string `json:"integrationType"`

	// Checks for cloudsec integrations
	AuditRoleStatus       *SourceIntegrationItemStatus `json:"auditRoleStatus"`
	CWERoleStatus         *SourceIntegrationItemStatus `json:"cweRoleStatus"`
	RemediationRoleStatus *SourceIntegrationItemStatus `json:"remediationRoleStatus"`

	// Checks for log analysis integrations
	ProcessingRoleStatus *SourceIntegrationItemStatus            `json:"processingRoleStatus"`
	S3BucketsStatus      map[string]*SourceIntegrationItemStatus `json:"s3BucketsStatus"`
	KMSKeysStatus        map[string]*SourceIntegrationItemStatus `json:"kmsKeysStatus"`
}

type SourceIntegrationItemStatus struct {
	Healthy      *bool   `json:"healthy"`
	ErrorMessage *string `json:"errorMessage"`
}

type SourceIntegrationTemplate struct {
	Body []byte `json:"body"`
}
