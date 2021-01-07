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
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"

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
	null []byte // this is '-' for empty fields
}

func NewAWSS3ServerAccess() *AWSS3ServerAccess {
	return &AWSS3ServerAccess{
		CSV:  *filegen.NewCSV().WithDelimiter(" "),
		null: []byte{'-'},
	}
}

func (sa *AWSS3ServerAccess) LogType() string {
	return AWSS3ServerAccessName
}

func (sa *AWSS3ServerAccess) Filename(_ time.Time) string {
	return uuid.New().String()
}

func (sa *AWSS3ServerAccess) NewFile(hour time.Time) *filegen.File {
	f := filegen.NewFile(sa, hour)
	var event awslogs.S3ServerAccess
	for i := 0; i < sa.Rows(); i++ {
		sa.fillEvent(&event, hour)
		sa.writeEvent(&event, f)
	}
	f.Close()
	return f
}

func (*AWSS3ServerAccess) fillEvent(event *awslogs.S3ServerAccess, hour time.Time) {
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

func (sa *AWSS3ServerAccess) writeEvent(event *awslogs.S3ServerAccess, w io.Writer) {
	eventTime := (*time.Time)(event.Time).Format("[2/Jan/2006:15:04:05 -0700]")

	sa.writeString(event.BucketOwner, w)
	sa.writeDelimiter(w)
	sa.writeString(event.Bucket, w)
	sa.writeDelimiter(w)
	sa.writeString(&eventTime, w)
	sa.writeDelimiter(w)
	sa.writeString(event.RemoteIP, w)
	sa.writeDelimiter(w)
	sa.writeString(event.Requester, w)
	sa.writeDelimiter(w)
	sa.writeString(event.RequestID, w)
	sa.writeDelimiter(w)
	sa.writeString(event.Operation, w)
	sa.writeDelimiter(w)
	sa.writeString(event.Key, w)
	sa.writeDelimiter(w)
	sa.writeString(event.RequestURI, w)
	sa.writeDelimiter(w)
	sa.writeInt(event.HTTPStatus, w)
	sa.writeDelimiter(w)
	sa.writeString(event.ErrorCode, w)
	sa.writeDelimiter(w)
	sa.writeInt(event.BytesSent, w)
	sa.writeDelimiter(w)
	sa.writeInt(event.ObjectSize, w)
	sa.writeDelimiter(w)
	sa.writeInt(event.TotalTime, w)
	sa.writeDelimiter(w)
	sa.writeInt(event.TurnAroundTime, w)
	sa.writeDelimiter(w)
	sa.writeString(event.Referrer, w)
	sa.writeDelimiter(w)
	sa.writeString(event.UserAgent, w)
	sa.writeDelimiter(w)
	sa.writeString(event.VersionID, w)
	sa.writeDelimiter(w)
	sa.writeString(event.HostID, w)
	sa.writeDelimiter(w)
	sa.writeString(event.SignatureVersion, w)
	sa.writeDelimiter(w)
	sa.writeString(event.CipherSuite, w)
	sa.writeDelimiter(w)
	sa.writeString(event.AuthenticationType, w)
	sa.writeDelimiter(w)
	sa.writeString(event.HostHeader, w)
	sa.writeDelimiter(w)
	sa.writeString(event.TLSVersion, w)

	sa.writeLineDelimiter(w)
}

func (sa *AWSS3ServerAccess) writeDelimiter(w io.Writer) {
	_, err := io.WriteString(w, sa.Delimiter())
	if err != nil {
		panic(err)
	}
}

func (sa *AWSS3ServerAccess) writeLineDelimiter(w io.Writer) {
	_, err := io.WriteString(w, sa.EndOfLine())
	if err != nil {
		panic(err)
	}
}

func (sa *AWSS3ServerAccess) writeString(s *string, w io.Writer) {
	var err error
	if s == nil {
		_, err = w.Write(sa.null)
	} else {
		_, err = io.WriteString(w, *s)
	}
	if err != nil {
		panic(err)
	}
}

func (sa *AWSS3ServerAccess) writeInt(i *int, w io.Writer) {
	var err error
	if i == nil {
		_, err = w.Write(sa.null)
	} else {
		_, err = io.WriteString(w, strconv.Itoa(*i))
	}
	if err != nil {
		panic(err)
	}
}
