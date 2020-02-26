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

// S3Notification is sent when new data is available in S3
type S3Notification struct {
	// S3Bucket is name of the S3 Bucket where data is available
	S3Bucket *string `json:"s3Bucket" validate:"required"`
	// S3ObjectKey is the key of the S3 object that contains the new data
	S3ObjectKey *string `json:"s3ObjectKey" validate:"required"`
	// Events is the number of events in the S3 object
	Events *int `json:"events" validate:"required"`
	// Bytes is the uncompressed size in bytes of the S3 object
	Bytes *int `json:"bytes" validate:"required"`
	// Type is the type of data available in the S3 object (LogData,RuleOutput)
	Type *string `json:"type" validate:"required"`
	// ID is an identified for the data in the S3 object. In case of LogData this will be
	// the Log Type, in case of RuleOutput data this will be the RuleID
	ID *string `json:"id" validate:"required"`
}

// The type of data that are stored in the Panther
type DataType string

const (
	// LogData represents log data processed by Panther
	LogData DataType = "LogData"
	// RuleData represents log data that have matched some rule
	RuleData DataType = "RuleMatches"
)

func (d DataType) String() string {
	return string(d)
}
