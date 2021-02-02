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
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/panther-labs/panther/cmd/devtools/filegen"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
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
		sa.writeEvent(&event, hour, f)
	}
	f.Close()
	return f
}

func (sa *AWSS3ServerAccess) writeEvent(event *awslogs.S3ServerAccess, hour time.Time, w io.Writer) {
	event.BucketOwner = box.String(filegen.StringAlphaNum(64))
	sa.writeString(event.BucketOwner, w, true)

	event.Bucket = box.String(filegen.String(64))
	sa.writeString(event.Bucket, w, true)

	sa.writeEventTime(hour, w)

	event.RemoteIP = box.String(filegen.IP())
	sa.writeString(event.RemoteIP, w, true)

	event.Requester = box.String(filegen.String(64))
	sa.writeString(event.Requester, w, true)

	event.RequestID = box.String(filegen.String(64))
	sa.writeString(event.RequestID, w, true)

	event.Operation = box.String(filegen.String(16))
	sa.writeString(event.Operation, w, true)

	event.Key = box.String(filegen.String(64))
	sa.writeString(event.Key, w, true)

	event.RequestURI = box.String(filegen.String(64))
	sa.writeString(event.RequestURI, w, true)

	event.HTTPStatus = box.Int(200)
	sa.writeInt(event.HTTPStatus, w)

	event.ErrorCode = box.String(filegen.String(8))
	sa.writeString(event.ErrorCode, w, true)

	event.BytesSent = box.Int(filegen.Intn(10000))
	sa.writeInt(event.BytesSent, w)

	event.ObjectSize = box.Int(filegen.Intn(10000))
	sa.writeInt(event.ObjectSize, w)

	event.TotalTime = box.Int(filegen.Intn(10000))
	sa.writeInt(event.TotalTime, w)

	event.TurnAroundTime = box.Int(filegen.Intn(10000))
	sa.writeInt(event.TurnAroundTime, w)

	event.Referrer = box.String(filegen.String(64))
	sa.writeString(event.Referrer, w, true)

	event.UserAgent = box.String(filegen.String(64))
	sa.writeString(event.UserAgent, w, true)

	event.VersionID = box.String(filegen.String(8))
	sa.writeString(event.VersionID, w, true)

	event.HostID = box.String(filegen.String(64))
	sa.writeString(event.HostID, w, true)

	event.SignatureVersion = box.String(filegen.String(8))
	sa.writeString(event.SignatureVersion, w, true)

	event.CipherSuite = box.String(filegen.String(16))
	sa.writeString(event.CipherSuite, w, true)

	event.AuthenticationType = box.String(filegen.String(64))
	sa.writeString(event.AuthenticationType, w, true)

	event.HostHeader = box.String(filegen.String(32))
	sa.writeString(event.HostHeader, w, true)

	event.TLSVersion = box.String(filegen.StringChoice(tlsVersions))
	sa.writeString(event.TLSVersion, w, false) // false! last element, write \n
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

var (
	tlsVersions = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "NULL"}
)

func (sa *AWSS3ServerAccess) writeString(s *string, w io.Writer, delimiter bool) {
	var err error
	if s == nil {
		_, err = w.Write(sa.null)
	} else {
		// ensure we do not inject any delimiters!
		_, err = io.WriteString(w, strings.Replace(*s, sa.Delimiter(), "d", -1))
	}
	if err != nil {
		panic(err)
	}
	if delimiter {
		sa.writeDelimiter(w)
	} else {
		sa.writeLineDelimiter(w)
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
	sa.writeDelimiter(w)
}

func (sa *AWSS3ServerAccess) writeEventTime(t time.Time, w io.Writer) {
	var err error
	_, err = io.WriteString(w, t.Format("[2/Jan/2006:15:04:05 -0700]"))
	if err != nil {
		panic(err)
	}
	sa.writeDelimiter(w)
}
