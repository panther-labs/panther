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
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypePostgres = `Juniper.Postgres`

var _ parsers.LogParser = (*PostgresParser)(nil)

type PostgresParser struct {
	timestampParser
}

func (p *PostgresParser) LogType() string {
	return TypePostgres
}

func (p *PostgresParser) Parse(log string) ([]*parsers.PantherLog, error) {
	match := rxPostgres.FindStringSubmatch(log)
	if len(match) == 0 {
		return nil, errors.New("invalid log line")
	}
	fields := struct {
		Timestamp    string
		Hostname     string
		PID          string
		GroupIDMajor string
		GroupIDMinor string
		SQLErrorCode string
		SessionID    string
		MessageType  string
		Message      string
	}{
		Timestamp:    match[1],
		Hostname:     match[2],
		PID:          match[3],
		GroupIDMajor: match[4],
		GroupIDMinor: match[5],
		SQLErrorCode: match[6],
		SessionID:    match[7],
		MessageType:  match[8],
		Message:      strings.TrimSpace(match[9]),
	}
	ts, err := p.ParseTimestamp(fields.Timestamp)
	if err != nil {
		return nil, err
	}
	pid, err := strconv.ParseInt(fields.PID, 10, 32)
	if err != nil {
		return nil, err
	}
	gidMajor, err := strconv.ParseInt(fields.GroupIDMajor, 10, 32)
	if err != nil {
		return nil, err
	}
	gidMinor, err := strconv.ParseInt(fields.GroupIDMinor, 10, 32)
	if err != nil {
		return nil, err
	}
	event := Postgres{
		Timestamp:    timestamp.RFC3339(ts),
		Hostname:     fields.Hostname,
		PID:          int32(pid),
		GroupIDMajor: int32(gidMajor),
		GroupIDMinor: int32(gidMinor),
		SQLErrorCode: fields.SQLErrorCode,
		SessionID:    fields.SessionID,
		MessageType:  fields.MessageType,
		Message:      fields.Message,
	}
	event.SetCoreFields(TypePostgres, &event.Timestamp, &event)
	return event.Logs(), nil
}

//nolint: lll
type Postgres struct {
	Timestamp    timestamp.RFC3339 `json:"timestamp" validate:"required,omitempty" description:"Log entry timestamp"`
	Hostname     string            `json:"hostname,omitempty" description:"The hostname of the appliance"`
	PID          int32             `json:"pid,omitempty" description:"The process ID of the postgres instance."`
	GroupIDMajor int32             `json:"group_id_major,omitempty" description:"Group id major number"`
	GroupIDMinor int32             `json:"group_id_minor,omitempty" description:"Group id minor number"`
	SQLErrorCode string            `json:"sql_error_code,omitempty" description:"The SQL error code."`
	SessionID    string            `json:"session_id,omitempty" description:"A somewhat unique session identifier that can be used to search for specific lines in the log."`
	MessageType  string            `json:"message_type,omitempty" description:"The type of the message. Can be LOG, WARNING, ERROR, or STATEMENT."`
	Message      string            `json:"message,omitempty" description:"The message."`

	parsers.PantherLog
}

func (p *PostgresParser) New() parsers.LogParser {
	return NewPostgresParser()
}

func NewPostgresParser() *PostgresParser {
	return &PostgresParser{
		timestampParser: timestampParser{
			Now: time.Now(),
		},
	}
}

var rxPostgres = regexp.MustCompile(fmt.Sprintf(
	`^(%s) (\S+) postgres\[(\d+)\]: \[(\d+)-(\d+)\] (\S+) (\S+) (\S+):\s*(.*)`,
	rxTimestamp,
))
