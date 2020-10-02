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

const (
	// IntegrationTypeAWSScan is the integration type for snapshots in customer AWS accounts.
	IntegrationTypeAWSScan = "aws-scan"
	// IntegrationTypeAWS3 is the integration type for importing data from customer S3 buckets.
	IntegrationTypeAWS3 = "aws-s3"
	// IntegrationTypeSqs is integration type for pulling data from an SQS queue.
	IntegrationTypeSqs = "aws-sqs"

	// StatusError is the string set in the database when an error occurs in a scan.
	StatusError = "error"
	// StatusOK is the string set in the database when a scan is successful.
	StatusOK = "ok"
	// StatusScanning is the status set while a scan is underway.
	StatusScanning = "scanning"
)
