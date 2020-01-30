package nginx

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

type Access struct {
	RemoteAddress *string            `json:"remoteAddr,omitempty"`
	RemoteUser    *string            `json:"remoteUser,omitempty"`
	Time          *timestamp.RFC3339 `json:"time" validate:"required"`
	Request       *string            `json:"request,omitempty"`
	Status        *int16             `json:"status,omitempty"`
	BodyBytesSent *int               `json:"bodyBytesSent,omitempty"`
	HTTPReferer   *string            `json:"httpReferer,omitempty"`
	HTTPUserAgent *string            `json:"httpUserAgent,omitempty"`
}

// AccessParser parses Nginx Access logs in 'combined' log format
type AccessParser struct{}

// Parse returns the parsed events or nil if parsing failed
func (p *AccessParser) Parse(log string) []interface{} {
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

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *AccessParser) LogType() string {
	return "Nginx.Access"
}
