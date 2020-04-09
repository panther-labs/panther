package ddb

/**
 * A Cloud-Native SIEM for the Modern Security Team
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

// UpdateIntegrationItem updates almost every attribute in the table.
//
// It's used for attributes that can change, which is almost all of them except for the
// creation based ones (CreatedAtTime and CreatedBy).
type UpdateIntegrationItem struct {
	RemediationEnabled   *bool      `json:"remediationEnabled"`
	CWEEnabled           *bool      `json:"cweEnabled"`
	IntegrationID        *string    `json:"integrationId"`
	IntegrationLabel     *string    `json:"integrationLabel"`
	IntegrationType      *string    `json:"integrationType"`
	LastScanEndTime      *time.Time `json:"lastScanEndTime"`
	LastScanErrorMessage *string    `json:"lastScanErrorMessage"`
	LastScanStartTime    *time.Time `json:"lastScanStartTime"`
	ScanStatus           *string    `json:"scanStatus"`
	ScanIntervalMins     *int       `json:"scanIntervalMins"`
	S3Bucket             *string    `json:"s3Bucket"`
	S3Prefix             *string    `json:"s3Prefix"`
	KmsKey               *string    `json:"kmsKey"`
	LogTypes             []*string  `json:"logTypes" dynamodbav:"logTypes,stringset"`
}
