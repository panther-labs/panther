package awslogs

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
	"encoding/csv"
	"strings"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var S3ServerAccessDesc = `S3ServerAccess is an AWS S3 Access Log.
Log format & samples can be seen here: https://docs.aws.amazon.com/AmazonS3/latest/dev/LogFormat.html`

const (
	s3ServerAccessMinNumberOfColumns = 25
)

type S3ServerAccess struct {
	BucketOwner        *string            `json:"bucketowner,omitempty" validate:"required,len=64,alphanum"`
	Bucket             *string            `json:"bucket,omitempty"`
	Time               *timestamp.RFC3339 `json:"time,omitempty"`
	RemoteIP           *string            `json:"remoteip,omitempty"`
	Requester          *string            `json:"requester,omitempty"`
	RequestID          *string            `json:"requestid,omitempty"`
	Operation          *string            `json:"operation,omitempty"`
	Key                *string            `json:"key,omitempty"`
	RequestURI         *string            `json:"requesturi,omitempty"`
	HTTPStatus         *int               `json:"httpstatus,omitempty" validate:"required,max=600,min=100"`
	ErrorCode          *string            `json:"errorcode,omitempty"`
	BytesSent          *int               `json:"bytessent,omitempty"`
	ObjectSize         *int               `json:"objectsize,omitempty"`
	TotalTime          *int               `json:"totaltime,omitempty"`
	TurnAroundTime     *int               `json:"turnaroundtime,omitempty"`
	Referrer           *string            `json:"referrer,omitempty"`
	UserAgent          *string            `json:"useragent,omitempty"`
	VersionID          *string            `json:"versionid,omitempty"`
	HostID             *string            `json:"hostid,omitempty"`
	SignatureVersion   *string            `json:"signatureversion,omitempty"`
	CipherSuite        *string            `json:"ciphersuite,omitempty"`
	AuthenticationType *string            `json:"authenticationtype,omitempty"`
	HostHeader         *string            `json:"hostheader,omitempty"`
	TLSVersion         *string            `json:"tlsVersion,omitempty"`
	AdditionalFields   []string           `json:"additionalFields,omitempty"`
}

// S3ServerAccessParser parses AWS S3 Server Access logs
type S3ServerAccessParser struct{}

// Parse returns the parsed events or nil if parsing failed
func (p *S3ServerAccessParser) Parse(log string) []interface{} {
	reader := csv.NewReader(strings.NewReader(log))
	reader.LazyQuotes = true
	reader.Comma = ' '

	records, err := reader.ReadAll()
	if len(records) == 0 || err != nil {
		zap.L().Debug("failed to parse the log as csv")
		return nil
	}

	// parser should only receive 1 line at a time
	record := records[0]
	if len(record) < s3ServerAccessMinNumberOfColumns {
		zap.L().Debug("failed to parse the log as csv (wrong number of columns)")
		return nil
	}

	// The time in the logs is represented as [06/Feb/2019:00:00:38 +0000]
	// The CSV reader will break the above date to two different fields `[06/Feb/2019:00:00:38` and `+0000]`
	// We concatenate these fields before trying to parse them
	parsedTime, err := timestamp.Parse("[2/Jan/2006:15:04:05-0700]", record[2]+record[3])
	if err != nil {
		zap.L().Debug("failed to parse timestamp log as csv")
		return nil
	}

	var additionalFields []string = nil
	if len(record) > 25 {
		additionalFields = record[25:]
	}

	event := &S3ServerAccess{
		BucketOwner:        parsers.CsvStringToPointer(record[0]),
		Bucket:             parsers.CsvStringToPointer(record[1]),
		Time:               &parsedTime,
		RemoteIP:           parsers.CsvStringToPointer(record[4]),
		Requester:          parsers.CsvStringToPointer(record[5]),
		RequestID:          parsers.CsvStringToPointer(record[6]),
		Operation:          parsers.CsvStringToPointer(record[7]),
		Key:                parsers.CsvStringToPointer(record[8]),
		RequestURI:         parsers.CsvStringToPointer(record[9]),
		HTTPStatus:         parsers.CsvStringToIntPointer(record[10]),
		ErrorCode:          parsers.CsvStringToPointer(record[11]),
		BytesSent:          parsers.CsvStringToIntPointer(record[12]),
		ObjectSize:         parsers.CsvStringToIntPointer(record[13]),
		TotalTime:          parsers.CsvStringToIntPointer(record[14]),
		TurnAroundTime:     parsers.CsvStringToIntPointer(record[15]),
		Referrer:           parsers.CsvStringToPointer(record[16]),
		UserAgent:          parsers.CsvStringToPointer(record[17]),
		VersionID:          parsers.CsvStringToPointer(record[18]),
		HostID:             parsers.CsvStringToPointer(record[19]),
		SignatureVersion:   parsers.CsvStringToPointer(record[20]),
		CipherSuite:        parsers.CsvStringToPointer(record[21]),
		AuthenticationType: parsers.CsvStringToPointer(record[22]),
		HostHeader:         parsers.CsvStringToPointer(record[23]),
		TLSVersion:         parsers.CsvStringToPointer(record[24]),
		AdditionalFields:   additionalFields,
	}

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *S3ServerAccessParser) LogType() string {
	return "AWS.S3ServerAccess"
}
