// Package juniperlogs provides parsers for Juniper logs
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
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// LogTypes exports the available log type entries
func LogTypes() logtypes.Group {
	return logTypes
}

// nolint:lll
var logTypes = logtypes.Must("Juniper",
	logtypes.Config{
		Name:         TypeAccess,
		Description:  TypeAccess + ` logs for all traffic coming to and from the box.`,
		ReferenceURL: `https://www.juniper.net/documentation/en_US/webapp5.6/topics/reference/w-a-s-access-log.html`,
		Schema:       Access{},
		NewParser:    parsers.AdapterFactory(&AccessParser{}),
	},
	logtypes.Config{
		Name:         TypeAudit,
		Description:  TypeAudit + ` The audit log contains log entries that indicate non-idempotent (state changing) actions performed on WebApp Secure.`,
		ReferenceURL: `https://www.juniper.net/documentation/en_US/webapp5.6/topics/reference/w-a-s-incident-log-format.html`,
		Schema:       Audit{},
		NewParser:    parsers.AdapterFactory(&AuditParser{}),
	},
	logtypes.Config{
		Name:         TypeFirewall,
		Description:  TypeFirewall + ` stores information about dropped packets from the iptables firewall.`,
		ReferenceURL: `https://www.juniper.net/documentation/en_US/webapp5.6/topics/reference/w-a-s-incident-log-format.html`,
		Schema:       Firewall{},
		NewParser:    parsers.AdapterFactory(&FirewallParser{}),
	},
	logtypes.Config{
		Name:         TypeMWS,
		Description:  TypeMWS + ` is the main log file for most WebApp Secure logging needs. All messages that don't have a specific log location are sent, by default, to mws.log.`,
		ReferenceURL: `https://www.juniper.net/documentation/en_US/webapp5.6/topics/reference/w-a-s-mws-log.html`,
		Schema:       MWS{},
		NewParser:    parsers.AdapterFactory(&MWSParser{}),
	},
	logtypes.Config{
		Name:         TypePostgres,
		Description:  TypePostgres + ` contains logs of manipulations on the schema of the database that WebApp Secure uses, as well as any errors that occurred during database operations.`,
		ReferenceURL: `https://www.juniper.net/documentation/en_US/webapp5.6/topics/reference/w-a-s-postgres-log.html`,
		Schema:       Postgres{},
		NewParser:    parsers.AdapterFactory(&PostgresParser{}),
	},
	logtypes.Config{
		Name: TypeSecurity,
		Description: TypeSecurity + ` Webapp Secure is configured to log security incidents to mws-security.log.
		All security alerts should be sent to security.log (previously named security-alert.log).
		There are different types of security incidents that will be a part of this log: new profiles, security incidents, new counter responses.`,
		ReferenceURL: `https://www.juniper.net/documentation/en_US/webapp5.6/topics/reference/w-a-s-log-format.html`,
		Schema:       Security{},
		NewParser:    parsers.AdapterFactory(&SecurityParser{}),
	},
)

const (
	rxBrackets  = `\[[^\]]*\]`
	rxQuoted    = `"[^"]*"`
	rxTimestamp = `\w+ \d+ \d{2}:\d{2}:\d{2}`
	rxLogLevel  = `\[(?:TRACE|DEBUG|INFO|WARN|ERROR)\]`
)

type timestampParser struct {
	Now time.Time
}

// ParseTimestamp parses juniper log timestamps.
// Juniper innovated in their log format by omitting the year.
// This makes parsing the logs more fun especially if we're around New Year's eve.
// This parser tries to guess the year of the log event by comparing the year at the time of parsing.
func (p *timestampParser) ParseTimestamp(s string) (time.Time, error) {
	const layoutTimestamp = `Jan 2 15:04:05`
	tm, err := time.ParseInLocation(layoutTimestamp, s, time.UTC)
	if err != nil {
		return time.Time{}, err
	}
	year, month := p.Now.Year(), p.Now.Month()
	if month == time.January && tm.Month() > month {
		year--
	}
	return tm.AddDate(year, 0, 0), nil
}
