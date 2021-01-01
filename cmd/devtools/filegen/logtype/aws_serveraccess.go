package logtype

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

import (
	"bytes"
	"strconv"
	"time"

	"github.com/panther-labs/panther/cmd/devtools/filegen"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
)

const (
	AWSS3ServerAccessName = awslogs.TypeS3ServerAccess
)

type AWSS3ServerAccess struct {
	filegen.CSV
}

func NewAWSS3ServerAccess() *AWSS3ServerAccess {
	return &AWSS3ServerAccess{
		CSV: *filegen.NewCSV().WithDelimiter(" "),
	}
}

func (f *AWSS3ServerAccess) NewFile(hour time.Time) *filegen.File {
	var event awslogs.S3ServerAccess
	var buffer bytes.Buffer
	for i := 0; i < f.Rows(); i++ {
		f.fillEvent(&event, hour)
		f.writeEvent(&event, &buffer)
	}
	return filegen.NewFile(AWSS3ServerAccessName, hour, bytes.NewReader(buffer.Bytes()))
}

func (f *AWSS3ServerAccess) fillEvent(event *awslogs.S3ServerAccess, hour time.Time) {
	event.BucketOwner = box.String(filegen.String(64))
	event.Bucket = box.String(filegen.String(64))
	event.Time = (*timestamp.RFC3339)(&hour)
	event.RemoteIP = box.String(filegen.IP())
	event.Requester = box.String(filegen.String(64))
	event.RequestID = box.String(filegen.String(64))
	event.Operation = box.String(filegen.String(16))
	event.Key = box.String(filegen.String(64))
	event.RequestURI = box.String(filegen.String(64))
	event.HTTPStatus = box.Int(200)
	event.ErrorCode = box.String(filegen.String(8))
	event.BytesSent = box.Int(filegen.Int())
	event.ObjectSize = box.Int(filegen.Int())
	event.TotalTime = box.Int(filegen.Int())
	event.TurnAroundTime = box.Int(filegen.Int())
	event.Referrer = box.String(filegen.String(64))
	event.UserAgent = box.String(filegen.String(64))
	event.VersionID = box.String(filegen.String(8))
	event.HostID = box.String(filegen.String(64))
	event.SignatureVersion = box.String(filegen.String(8))
	event.CipherSuite = box.String(filegen.String(16))
	event.AuthenticationType = box.String(filegen.String(64))
	event.HostHeader = box.String(filegen.String(32))
	event.TLSVersion = box.String(filegen.String(8))
}

func (f *AWSS3ServerAccess) writeEvent(event *awslogs.S3ServerAccess, buffer *bytes.Buffer) {
	eventTime := (*time.Time)(event.Time).Format("[2/Jan/2006:15:04:05-0700]")

	f.writeString(event.BucketOwner, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.Bucket, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(&eventTime, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.RemoteIP, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.Requester, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.RequestID, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.Operation, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.Key, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.RequestURI, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeInt(event.HTTPStatus, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.ErrorCode, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeInt(event.BytesSent, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeInt(event.ObjectSize, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeInt(event.TotalTime, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeInt(event.TurnAroundTime, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.Referrer, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.UserAgent, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.VersionID, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.HostID, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.SignatureVersion, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.CipherSuite, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.AuthenticationType, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.HostHeader, buffer)
	buffer.WriteString(f.Delimiter())
	f.writeString(event.TLSVersion, buffer)

	buffer.WriteString("\n")
}

func (f *AWSS3ServerAccess) writeString(s *string, buffer *bytes.Buffer) {
	if s == nil {
		buffer.WriteString("-")
	} else {
		buffer.WriteString(*s)
	}
}

func (f *AWSS3ServerAccess) writeInt(i *int, buffer *bytes.Buffer) {
	if i == nil {
		buffer.WriteString("-")
	} else {
		buffer.WriteString(strconv.Itoa(*i))
	}
}
