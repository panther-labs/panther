package awslogs

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
	"errors"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/csvstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// FIXME: SQL statement can cause MIS parsing, needs review and testing.
const (
	TypeAuroraMySQLAudit               = "AWS.AuroraMySQLAudit"
	auroraMySQLAuditMinNumberOfColumns = 9
)

var LogTypeAuroraMySQLAudit = parsers.LogType{
	Name: TypeAuroraMySQLAudit,
	Description: `AuroraMySQLAudit is an RDS Aurora audit log which contains context around database calls.
Reference: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html`,
	Schema: struct {
		AuroraMySQLAudit
		Meta
	}{},
	NewParser: NewAuroraMySQLAuditParser,
}

// nolint:lll
type AuroraMySQLAudit struct {
	Timestamp    *timestamp.RFC3339 `json:"timestamp,omitempty" description:"The timestamp for the logged event with microsecond precision (UTC)."`
	ServerHost   *string            `json:"serverHost,omitempty" description:"The name of the instance that the event is logged for."`
	Username     *string            `json:"username,omitempty" description:"The connected user name of the user."`
	Host         *string            `json:"host,omitempty" description:"The host that the user connected from."`
	ConnectionID *int               `json:"connectionId,omitempty" description:"The connection ID number for the logged operation."`
	QueryID      *int               `json:"queryId,omitempty" description:"The query ID number, which can be used for finding the relational table events and related queries. For TABLE events, multiple lines are added."`
	Operation    *string            `json:"operation,omitempty" validate:"oneof=CONNECT QUERY READ WRITE CREATE ALTER RENAME DROP" description:"The recorded action type. Possible values are: CONNECT, QUERY, READ, WRITE, CREATE, ALTER, RENAME, and DROP."`
	Database     *string            `json:"database,omitempty" description:"The active database, as set by the USE command."`
	Object       *string            `json:"object,omitempty" description:"For QUERY events, this value indicates the executed query. For TABLE events, it indicates the table name."`
	RetCode      *int               `json:"retCode,omitempty" description:"The return code of the logged operation."`
}

var _ parsers.PantherEventer = (*AuroraMySQLAudit)(nil)

func (event *AuroraMySQLAudit) PantherEvent() *logs.Event {
	return logs.NewEvent(TypeAuroraMySQLAudit, event.Timestamp.UTC(),
		logs.IPAddress(aws.StringValue(event.Host)),
		logs.DomainName(aws.StringValue(event.ServerHost)),
	)
}

// AuroraMySQLAuditParser parses AWS Aurora MySQL Audit logs
type AuroraMySQLAuditParser struct {
	CSVReader *csvstream.StreamingCSVReader
}

var _ parsers.Interface = (*AuroraMySQLAuditParser)(nil)

func NewAuroraMySQLAuditParser() parsers.Interface {
	return &AuroraMySQLAuditParser{
		CSVReader: csvstream.NewStreamingCSVReader(),
	}
}

// Parse returns the parsed events or nil if parsing failed
func (p *AuroraMySQLAuditParser) Parse(log string) ([]*parsers.Result, error) {
	record, err := p.CSVReader.Parse(log)
	if err != nil {
		return nil, err
	}

	if len(record) < auroraMySQLAuditMinNumberOfColumns {
		return nil, errors.New("invalid number of columns")
	}

	timestampUnixMillis, err := strconv.ParseInt(record[0], 0, 64)
	if err != nil {
		return nil, err
	}

	// If there are ',' in the "object" field, CSV reader will split it to multiple fields
	// We are concatenating them to re-create the field
	objectString := strings.Join(record[8:len(record)-1], ",")

	timeStamp := timestamp.Unix(timestampUnixMillis/1000000, timestampUnixMillis%1000000*1000)

	event := &AuroraMySQLAudit{
		Timestamp:    &timeStamp,
		ServerHost:   parsers.CsvStringToPointer(record[1]),
		Username:     parsers.CsvStringToPointer(record[2]),
		Host:         parsers.CsvStringToPointer(record[3]),
		ConnectionID: parsers.CsvStringToIntPointer(record[4]),
		QueryID:      parsers.CsvStringToIntPointer(record[5]),
		Operation:    parsers.CsvStringToPointer(record[6]),
		Database:     parsers.CsvStringToPointer(record[7]),
		Object:       parsers.CsvStringToPointer(objectString),
		RetCode:      parsers.CsvStringToIntPointer(record[len(record)-1]),
	}

	return parsers.PackResults(event)
}
