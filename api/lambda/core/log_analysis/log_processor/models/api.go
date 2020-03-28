package models

import "github.com/aws/aws-lambda-go/events"

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
	// https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
	Records []events.S3EventRecord
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
