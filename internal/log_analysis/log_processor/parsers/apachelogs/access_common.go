package apachelogs

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
	"regexp"
	"strconv"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// LogFormat "%h %l %u %t \"%r\" %>s %b" common
// nolint:lll
type AccessCommon struct {
	AccessCommonLog
	parsers.PantherLog
}

// nolint:lll
type AccessCommonLog struct {
	RemoteHostIPAddress   *string            `json:"remote_host_ip_address" description:"This is the IP address of the client (remote host) which made the request to the server. If HostnameLookups is set to On, then the server will try to determine the hostname and log it in place of the IP address."`
	ClientIdentityRFC1413 *string            `json:"client_identity_rfc_1413,omitempty" description:"The RFC 1413 identity of the client determined by identd on the clients machine."`
	UserID                *string            `json:"request_user,omitempty" description:"The userid of the person requesting the document as determined by HTTP authentication. "`
	RequestTime           *timestamp.RFC3339 `json:"request_time,omitempty" description:"The time that the request was received."`
	RequestMethod         *string            `json:"request_method,omitempty" description:"The HTTP request method"`
	RequestURI            *string            `json:"request_uri,omitempty" description:"The HTTP request URI"`
	RequestProtocol       *string            `json:"request_protocol,omitempty" description:"The HTTP request protocol"`
	ResponseStatus        *int16             `json:"response_status" description:"The HTTP status of the response"`
	ResponseSize          *int64             `json:"response_size,omitempty" description:"The size of the HTTP response in bytes"`
}

type AccessCommonParser struct{}

func NewAccessCommonParser() parsers.LogParser {
	return &AccessCommonParser{}
}

func (p *AccessCommonParser) New() parsers.LogParser {
	return NewAccessCommonParser()
}

func (p *AccessCommonParser) LogType() string {
	return TypeAccessCommon
}

func (p *AccessCommonParser) Parse(log string) ([]*parsers.PantherLog, error) {
	access := AccessCommon{}
	if err := access.ParseString(log); err != nil {
		return nil, err
	}
	access.updatePantherFields(&access.PantherLog)

	return access.Logs(), nil
}

func (log *AccessCommonLog) ParseString(s string) error {
	match := rxAccessCommon.FindStringSubmatch(s)
	if len(match) > 1 {
		return log.SetRow(match[1:])
	}
	return errors.New("invalid log format")
}

var rxAccessCommon = regexp.MustCompile(buildRx(
	rxUnquoted,   // remoteIP
	rxUnquoted,   // clientID
	rxUnquoted,   // userID
	rxBrackets,   // requestTime
	rxQuoted,     // requestLine
	rxStatusCode, // responseStatus
	rxSize,       // responseSize
))

func (log *AccessCommonLog) SetRow(row []string) error {
	if len(row) == numFieldsAccessCommon {
		// Assignment in single line right after len check avoids bounds checks on fields
		// nolint:lll
		remoteIP, idRFC1413, userID, requestTime, requestLine, responseStatus, responseSize := row[0], row[1], row[2], row[3], row[4], row[5], row[6]
		tm, err := timestamp.Parse(layoutApacheTimestamp, requestTime)
		if err != nil {
			return err
		}
		req := httpRequestLine{}
		if err := req.ParseString(requestLine); err != nil {
			return err
		}
		n, err := strconv.ParseInt(responseStatus, 10, 16)
		if err != nil {
			return err
		}
		statusCode := int16(n)

		var numBytes int64
		if nonEmptyLogField(responseSize) != nil {
			numBytes, err = strconv.ParseInt(responseSize, 10, 64)
			if err != nil {
				return err
			}
		}

		*log = AccessCommonLog{
			RemoteHostIPAddress:   nonEmptyLogField(remoteIP),
			ClientIdentityRFC1413: nonEmptyLogField(idRFC1413),
			UserID:                nonEmptyLogField(userID),
			RequestTime:           &tm,
			RequestMethod:         &req.Method,
			RequestProtocol:       &req.Protocol,
			RequestURI:            &req.URI,
			ResponseSize:          &numBytes,
			ResponseStatus:        &statusCode,
		}
		return nil
	}
	return errors.Errorf("invalid number of fields %d", len(row))
}

func (event *AccessCommon) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeAccessCommon, event.RequestTime, event)
	if !p.AppendAnyIPAddressPtr(event.RemoteHostIPAddress) {
		// Handle cases where apache config has resolved addresses enabled
		p.AppendAnyDomainNamePtrs(event.RemoteHostIPAddress)
	}
}
