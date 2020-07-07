package juniperlogs

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
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeAccess = `Juniper.Access`

var _ parsers.LogParser = (*AccessParser)(nil)

type AccessParser struct {
	timestampParser
	// rxMatchedOnce marks that at least one line has already matched.
	rxMatchedOnce bool
}

func NewAccessParser() *AccessParser {
	return &AccessParser{
		timestampParser: timestampParser{
			Now: time.Now(),
		},
	}
}

func (p *AccessParser) LogType() string {
	return TypeAccess
}
func (p *AccessParser) New() parsers.LogParser {
	return NewAccessParser()
}

func (p *AccessParser) Parse(log string) ([]*parsers.PantherLog, error) {
	match := rxAccess.FindStringSubmatch(log)
	if len(match) == 0 {
		// Juniper.Access log files only contain access logs. A single log event can span multiple lines.
		// The `rxAccess` expression matches only the first line of every event in the file.
		// The first non-empty line in a file should always match while using the parser in the log processing pipeline.
		// All subsequent lines describing event headers and body should be skipped without an error if we have managed
		// to match at least one log line previously.
		if p.rxMatchedOnce {
			// Return nil result and no error
			return nil, nil
		}
		// No lines were previously matched, the file is not a Juniper.Access log file.
		return nil, errors.New("invalid log line")
	}

	// We are confident that the file is a valid Juniper.Access log file.
	// The regular expression is specific enough and `FindStringSubmatch()` returns matches only if *all* non-optional
	// sub-groups are matched.
	p.rxMatchedOnce = true

	fields := struct {
		Timestamp     string
		Hostname      string
		LogLevel      string
		Thread        string
		RequestKey    string
		PacketType    string
		PacketStage   string
		ProxyClientIP string
		URL           string
	}{
		Timestamp:     match[1],
		Hostname:      match[2],
		LogLevel:      match[3],
		Thread:        match[4],
		RequestKey:    match[5],
		PacketType:    match[6],
		PacketStage:   match[7],
		ProxyClientIP: match[8],
		URL:           match[9],
	}

	ts, err := p.ParseTimestamp(fields.Timestamp)
	if err != nil {
		// This error will probably never happen.
		// It is kept just in case we encounter a specific scenario where the timestamp parser
		// cannot determine the year of the event.
		return nil, err
	}
	event := Access{
		Timestamp:     timestamp.RFC3339(ts),
		Hostname:      fields.Hostname,
		LogLevel:      strings.Trim(fields.LogLevel, "[]"),
		Thread:        fields.Thread,
		RequestKey:    fields.RequestKey,
		PacketType:    fields.PacketType,
		PacketStage:   fields.PacketStage,
		ProxyClientIP: fields.ProxyClientIP,
		URL:           fields.URL,
	}
	event.SetCoreFields(TypeAccess, &event.Timestamp, &event)
	event.AppendAnyIPAddress(event.ProxyClientIP)
	return event.Logs(), nil
}

// nolint:lll
var rxAccess = regexp.MustCompile(fmt.Sprintf(
	`^(%s) (\S+) \[(INFO|TRACE|DEBUG|WARN|ERROR)\]\[mws-access\]\[(\S+)\]\s*key:(\S+)\s*,\s*PHASE_(REQUEST|RESPONSE)_(PRE|POST)_PROCESS\s*,\s*(\S+)\s*,\s*(\S+)\s*$`,
	rxTimestamp,
))

// nolint:lll
type Access struct {
	Timestamp     timestamp.RFC3339 `json:"timestamp" validate:"required,omitempty" description:"Log entry timestamp"`
	Hostname      string            `json:"hostname,omitempty" description:"The hostname of the appliance"`
	LogLevel      string            `json:"log_level,omitempty" description:"The importance level of a log entry. Can be TRACE, DEBUG, INFO, WARN, or ERROR."`
	Thread        string            `json:"thread,omitempty" description:"The specific thread that is handling the request or response."`
	RequestKey    string            `json:"unique_request_key,omitempty" description:"This is a key used to uniquely identify requests."`
	PacketType    string            `json:"type,omitempty" description:"Whether the HTTP packet is a client request, or a server response (REQUEST,RESPONSE)."`
	PacketStage   string            `json:"stage,omitempty" description:"Whether the HTTP packet is being logged before or after Security Engine processes it (and potentially manipulates it)."`
	ProxyClientIP string            `json:"proxy_client_ip,omitempty" description:"The incoming client IP. Since WebApp Secure works around a Nginx proxy, the client IP will most-likely be '127.0.0.1'."`
	URL           string            `json:"url,omitempty" description:"The full request or response URL."`

	parsers.PantherLog
}
