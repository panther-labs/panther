package nginxlogs

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

const (
	accessNumberOfColumns = 10
	// User Identifier field - the second field in the logs - is always '-' for Nginx Access
	accessUserIdentifier           = "-"
	accessTimestampFormatTimeLocal = "[2/Jan/2006:15:04:05-0700]"
)

var AccessDesc = `Access Logs for your Nginx server. We currently support Nginx 'combined' format. 
Reference: http://nginx.org/en/docs/http/ngx_http_log_module.html#log_format`

// nolint:lll
type Access struct {
	RemoteAddress *string            `json:"remoteAddr,omitempty" description:"The IP address of the client (remote host) which made the request to the server."`
	RemoteUser    *string            `json:"remoteUser,omitempty" description:"The userid of the person making the request. Usually empty unless .htaccess has requested authentication."`
	Time          *timestamp.RFC3339 `json:"time" validate:"required" description:"The time that the request was received (UTC)."`
	Request       *string            `json:"request,omitempty" description:"The request line from the client. It includes the HTTP method, the resource requested, and the HTTP protocol."`
	Status        *int16             `json:"status,omitempty" description:"The HTTP status code returned to the client."`
	BodyBytesSent *int               `json:"bodyBytesSent,omitempty" description:"The size of the object returned to the client, measured in bytes."`
	HTTPReferer   *string            `json:"httpReferer,omitempty" description:"The HTTP referrer if any."`
	HTTPUserAgent *string            `json:"httpUserAgent,omitempty" description:"The agent the user used when making the request."`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// AccessParser parses Nginx Access logs in 'combined' log format
type AccessParser struct{}

func (p *AccessParser) New() parsers.LogParser {
	return &AccessParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *AccessParser) Parse(log string) []*parsers.PantherLog {
	reader := csv.NewReader(strings.NewReader(log))
	// Separator between fields is the empty space
	reader.Comma = ' '

	records, err := reader.ReadAll()
	if len(records) == 0 || err != nil {
		zap.L().Debug("failed to parse log (no records found)")
		return nil
	}

	// parser should only receive 1 line at a time
	if len(records) > 1 {
		zap.L().Debug("failed to parse log (parser expected one log line)")
		return nil
	}
	record := records[0]

	if len(record) != accessNumberOfColumns {
		zap.L().Debug("failed to parse log (wrong number of columns)")
		return nil
	}

	if record[1] != accessUserIdentifier {
		zap.L().Debug("failed to parse log (user identifier should always be '-')")
		return nil
	}

	// The time in the logs is represented as [06/Feb/2019:00:00:38 +0000]
	// The CSV reader will break the above date to two different fields `[06/Feb/2019:00:00:38` and `+0000]`
	// We concatenate these fields before trying to parse them
	parsedTime, err := timestamp.Parse(accessTimestampFormatTimeLocal, record[3]+record[4])
	if err != nil {
		zap.L().Debug("failed to parse time")
		return nil
	}

	event := &Access{
		RemoteAddress: parsers.CsvStringToPointer(record[0]),
		RemoteUser:    parsers.CsvStringToPointer(record[2]),
		Time:          &parsedTime,
		Request:       parsers.CsvStringToPointer(record[5]),
		Status:        parsers.CsvStringToInt16Pointer(record[6]),
		BodyBytesSent: parsers.CsvStringToIntPointer(record[7]),
		HTTPReferer:   parsers.CsvStringToPointer(record[8]),
		HTTPUserAgent: parsers.CsvStringToPointer(record[9]),
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *AccessParser) LogType() string {
	return "Nginx.Access"
}

func (event *Access) updatePantherFields(p *AccessParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
	event.AppendAnyIPAddressPtrs(event.RemoteAddress)
}
