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

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	CheckIntegration *CheckIntegrationInput `json:"integrationHealthCheck"`

	PutIntegration *PutIntegrationInput `json:"putIntegration"`

	ListIntegrations *ListIntegrationsInput `json:"getEnabledIntegrations"`

	UpdateIntegrationLastScanEnd   *UpdateIntegrationLastScanEndInput   `json:"updateIntegrationLastScanEnd"`
	UpdateIntegrationLastScanStart *UpdateIntegrationLastScanStartInput `json:"updateIntegrationLastScanStart"`
	UpdateIntegrationSettings      *UpdateIntegrationSettingsInput      `json:"updateIntegrationSettings"`

	DeleteIntegration *DeleteIntegrationInput `json:"deleteIntegration"`
}

//
// CheckIntegration: Used by the UI to determine integration status
//

// CheckIntegrationInput is used to check the health of a potential configuration.
type CheckIntegrationInput struct {
	AWSAccountID    *string `genericapi:"redact" json:"awsAccountId" validate:"required,len=12,numeric"`
	IntegrationType *string `json:"integrationType" validate:"required,oneof=aws-scan aws-s3"`

	// Checks for cloudsec integrations
	EnableCWESetup    *bool `json:"enableCWESetup"`
	EnableRemediation *bool `json:"enableRemediation"`

	// Checks for log analysis integrations
	S3Buckets []*string `json:"s3Buckets"`
	KmsKeys   []*string `json:"kmsKeys"`
}

//
// PutIntegration: Used by the UI
//

// PutIntegrationInput is used to add one or many integrations.
type PutIntegrationInput struct {
	Integrations  []*PutIntegrationSettings `json:"integrations" validate:"required,dive"`
	SkipScanQueue *bool                     `json:"skipScanQueue"`
}

// PutIntegrationSettings are all the settings for the new integration.
type PutIntegrationSettings struct {
	AWSAccountID     *string   `genericapi:"redact" json:"awsAccountId" validate:"required,len=12,numeric"`
	IntegrationLabel *string   `json:"integrationLabel,omitempty" validate:"omitempty,min=1"`
	IntegrationType  *string   `json:"integrationType" validate:"required,oneof=aws-scan aws-s3"`
	ScanEnabled      *bool     `json:"scanEnabled,omitempty"`
	ScanIntervalMins *int      `json:"scanIntervalMins,omitempty" validate:"omitempty,oneof=60 180 360 720 1440"`
	UserID           *string   `json:"userId" validate:"required,uuid4"`
	S3Buckets        []*string `json:"s3Buckets"`
	KmsKeys          []*string `json:"kmsKeys"`
}

//
// ListIntegrations: Used by the Scheduler
//

// ListIntegrationsInput allows filtering by the IntegrationType or Enabled fields
type ListIntegrationsInput struct {
	ScanEnabled     *bool   `json:"scanEnabled"`
	IntegrationType *string `json:"integrationType" validate:"oneof=aws-scan aws-s3"`
}

//
// DeleteIntegration: Used by the UI
//

// DeleteIntegrationInput is used to delete a specific item from the database.
type DeleteIntegrationInput struct {
	IntegrationID *string `json:"integrationId" validate:"required,uuid4"`
}

//
// UpdateIntegration: Used by the UI
//

// UpdateIntegrationLastScanStartInput is used to update scan information at the beginning of a scan.
type UpdateIntegrationLastScanStartInput struct {
	IntegrationID     *string    `json:"integrationId" validate:"required,uuid4"`
	LastScanStartTime *time.Time `json:"lastScanStartTime" validate:"required"`
	ScanStatus        *string    `json:"scanStatus" validate:"required,oneof=ok error scanning"`
}

// UpdateIntegrationLastScanEndInput is used to update scan information at the end of a scan.
type UpdateIntegrationLastScanEndInput struct {
	EventStatus          *string    `json:"eventStatus"`
	IntegrationID        *string    `json:"integrationId" validate:"required,uuid4"`
	LastScanEndTime      *time.Time `json:"lastScanEndTime" validate:"required"`
	LastScanErrorMessage *string    `json:"lastScanErrorMessage"`
	ScanStatus           *string    `json:"scanStatus" validate:"required,oneof=ok error scanning"`
}

// UpdateIntegrationSettingsInput is used to update integration settings.
type UpdateIntegrationSettingsInput struct {
	IntegrationID    *string   `json:"integrationId" validate:"required,uuid4"`
	IntegrationLabel *string   `json:"integrationLabel,omitempty" validate:"omitempty,min=1"`
	ScanEnabled      *bool     `json:"scanEnabled"`
	ScanIntervalMins *int      `json:"scanIntervalMins" validate:"omitempty,oneof=60 180 360 720 1440"`
	S3Buckets        []*string `json:"s3Buckets"`
	KmsKeys          []*string `json:"kmsKeys"`
}
