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
