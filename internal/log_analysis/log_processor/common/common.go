package common

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
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	MaxRetries = 20 // setting Max Retries to a higher number - we'd like to retry VERY hard before failing.
)

// Session AWS Session that can be used by components of the system
var Session = session.Must(session.NewSession(aws.NewConfig().WithMaxRetries(MaxRetries)))

// ParsedEvent contains a single event that has already been processed
type ParsedEvent struct {
	Event   interface{} `json:"event"`
	LogType string      `json:"logType"`
}

// DataStream represents a data stream that read by the processor
type DataStream struct {
	Reader io.Reader
	Hints  DataStreamHints
	// The log type if known
	// If it is nil, it means the log type hasn't been identified yet
	LogType *string
}

// Used in a DataStream as meta data to describe the data
type DataStreamHints struct {
	S3 *S3DataStreamHints // if nil, no hint
}

// Used in a DataStreamHints as meta data to describe the S3 object backing the stream
type S3DataStreamHints struct {
	Bucket      string
	Key         string
	ContentType string
}

// S3Notification is sent when new data is available in S3
type S3Notification struct {
	// S3Bucket is name of the S3 Bucket where data is available
	S3Bucket *string `json:"s3Bucket,omitempty"`
	// S3ObjectKey is the key of the S3 object that contains the new data
	S3ObjectKey *string `json:"s3ObjectKey,omitempty"`
	// Events is the number of events in the S3 object
	Events *int `json:"events,omitempty"`
	// Bytes is the uncompressed size in bytes of the S3 object
	Bytes *int `json:"bytes,omitempty"`
	// Type is the type of data available in the S3 object (LogData,RuleOutput)
	Type *string `json:"type,omitempty"`
	// ID is an identified for the data in the S3 object. In case of LogData this will be
	// the Log Type, in case of RuleOutput data this will be the RuleID
	ID *string `json:"id,omitempty"`
}

const (
	LogData    = "LogData"
	RuleOutput = "RuleOutput"
)
