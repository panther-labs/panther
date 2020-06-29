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

const TypeAudit = `Juniper.Audit`

type AuditParser struct {
	timestampParser
}

func (p *AuditParser) LogType() string {
	return TypeAudit
}

func (p *AuditParser) Parse(log string) ([]*parsers.PantherLog, error) {
	match := rxAudit.FindStringSubmatch(log)
	if len(match) == 0 {
		return nil, errors.New("invalid log line")
	}
	fields := struct {
		Timestamp    string
		Hostname     string
		LogLevel     string
		APIKeyOrUser string
		IPAddress    string
		Message      string
	}{
		Timestamp: match[1],
		Hostname:  match[2],
		// Audit always has log level, trim here
		LogLevel:     strings.Trim(match[3], "[]"),
		APIKeyOrUser: strings.Trim(match[4], "[]"),
		IPAddress:    match[5],
		Message:      strings.TrimSpace(match[6]),
	}
	tm, err := p.ParseTimestamp(fields.Timestamp)
	if err != nil {
		return nil, err
	}
	event := Audit{
		Timestamp: timestamp.RFC3339(tm),
		Hostname:  fields.Hostname,
		LogLevel:  fields.LogLevel,
		Message:   fields.Message,
	}
	if fields.IPAddress != "" {
		addr := strings.Trim(fields.IPAddress, `[]`)
		event.LoginIP = &addr
		event.Username = &fields.APIKeyOrUser
	} else if rxAPIKey.MatchString(fields.APIKeyOrUser) {
		// The 4th match is ambiguous. It can be either username or api_key.
		// A username of 32 hex-only characters is rather unusual so it's safe(?) to assume it is an api key.
		event.APIKey = &fields.APIKeyOrUser
	} else {
		event.Username = &fields.APIKeyOrUser
	}

	event.SetCoreFields(TypeAudit, &event.Timestamp, &event)
	if event.LoginIP != nil {
		event.AppendAnyIPAddress(*event.LoginIP)
	}
	return event.Logs(), nil
}

func (p *AuditParser) New() parsers.LogParser {
	return NewAuditParser()
}

func NewAuditParser() *AuditParser {
	return &AuditParser{
		timestampParser: timestampParser{
			Now: time.Now(),
		},
	}
}

var _ parsers.LogParser = (*AuditParser)(nil)

// nolint:lll
type Audit struct {
	Timestamp timestamp.RFC3339 `json:"timestamp" validate:"required,omitempty" description:"Log entry timestamp"`
	Hostname  string            `json:"hostname,omitempty" description:"The hostname of the appliance"`
	LogLevel  string            `json:"log_level,omitempty" description:"The importance level of a log entry. Can be TRACE, DEBUG, INFO, WARN, or ERROR."`
	Message   string            `json:"message,omitempty" description:"The message. Can indicate any of the previously mentioned actions."`
	APIKey    *string           `json:"api_key,omitempty" description:"The key used to perform the action described in the message."`
	LoginIP   *string           `json:"login_ip,omitempty" description:"The IP address the user performed logged in from"`
	Username  *string           `json:"username,omitempty" description:"The user that performed the login"`

	parsers.PantherLog
}

var rxAudit = regexp.MustCompile(fmt.Sprintf(
	`^(%s) (\S+) \[mws-audit\](%s)\s*(%s)?\s*(%s)?\s+(.*)$`,
	rxTimestamp,
	rxBrackets,
	rxBrackets,
	rxBrackets,
))

var rxAPIKey = regexp.MustCompile(`^[a-f0-9]{32}$`)
