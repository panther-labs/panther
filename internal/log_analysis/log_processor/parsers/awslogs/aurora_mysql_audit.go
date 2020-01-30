package awslogs

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
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var AuroraMySQLAuditDesc = `AuroraMySQLAudit is an RDS Aurora audit log which contains context around database calls.
Reference: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html`

// FIXME: SQL statement can cause MIS parsing, needs review and testing.
const (
	auroraMySQLAuditMinNumberOfColumns = 9
)

type AuroraMySQLAudit struct {
	Timestamp    *timestamp.RFC3339 `json:"timestamp,omitempty"`
	ServerHost   *string            `json:"serverHost,omitempty"`
	Username     *string            `json:"username,omitempty"`
	Host         *string            `json:"host,omitempty"`
	ConnectionID *int               `json:"connectionId,omitempty"`
	QueryID      *int               `json:"queryId,omitempty"`
	Operation    *string            `json:"operation,omitempty" validate:"oneof=CONNECT QUERY READ WRITE CREATE ALTER RENAME DROP"`
	Database     *string            `json:"database,omitempty"`
	Object       *string            `json:"object,omitempty"`
	RetCode      *int               `json:"retCode,omitempty"`
}

// AuroraMySQLAuditParser parses AWS Aurora MySQL Audit logs
type AuroraMySQLAuditParser struct{}

// Parse returns the parsed events or nil if parsing failed
func (p *AuroraMySQLAuditParser) Parse(log string) []interface{} {
	reader := csv.NewReader(strings.NewReader(log))
	records, err := reader.ReadAll()
	if len(records) == 0 || err != nil {
		zap.L().Debug("failed to parse the log as csv")
		return nil
	}

	// parser should only receive 1 line at a time
	record := records[0]
	if len(record) < auroraMySQLAuditMinNumberOfColumns {
		zap.L().Debug("failed to parse the log as csv (wrong number of columns)")
		return nil
	}

	timestampUnixMillis, err := strconv.ParseInt(record[0], 0, 64)
	if err != nil {
		return nil
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
	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *AuroraMySQLAuditParser) LogType() string {
	return "AWS.AuroraMySQLAudit"
}
