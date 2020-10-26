package fastlylogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/apachelogs"
)

const TypeAccess = "Fastly.Access"

type Access = apachelogs.AccessCommon // Log format is the same (CLF)

type AccessParser struct {
	apachelogs.AccessCommonParser
}

func (*AccessParser) New() parsers.LogParser {
	return &AccessParser{}
}

func (*AccessParser) LogType() string {
	return TypeAccess
}

func (p *AccessParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := Access{}
	if err := event.ParseString(log); err != nil {
		return nil, err
	}

	// Update panther fields.
	pantherlog := &event.PantherLog
	pantherlog.SetCoreFields(p.LogType(), event.RequestTime, &event)
	if !pantherlog.AppendAnyIPAddressPtr(event.RemoteHostIPAddress) {
		// Handle cases where field is a domain instead of an IP.
		pantherlog.AppendAnyDomainNamePtrs(event.RemoteHostIPAddress)
	}

	return event.Logs(), nil
}

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("Fastly", logtypes.Config{
	Name: TypeAccess,
	Description: `Fastly logs in the Common Log Format. To ensure Panther can parse the logs, make sure
to select "Blank" in the "Log line format" field when creating an S3 logging endpoint for your Fastly service.`,
	ReferenceURL: `https://docs.fastly.com/en/guides/useful-log-formats#common-log-format-clf`,
	Schema:       Access{},
	NewParser:    parsers.AdapterFactory(&AccessParser{}),
})
