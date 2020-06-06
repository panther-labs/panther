package osquerylogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	TypeBatch        = "Osquery.Batch"
	TypeDifferential = "Osquery.Differential"
	TypeSnapshot     = "Osquery.Snapshot"
	TypeStatus       = "Osquery.Status"
)

func init() {
	pantherlog.MustRegister(
		pantherlog.EventType{
			Name:         TypeBatch,
			Description:  `Batch contains all the data included in OsQuery batch logs`,
			ReferenceURL: `https://osquery.readthedocs.io/en/stable/deployment/logging/`,
			Schema:       Batch{},
			NewParser:    parsers.AdapterFactory(&BatchParser{}),
		},
		pantherlog.EventType{
			Name:         TypeDifferential,
			Description:  `Differential contains all the data included in OsQuery differential logs`,
			ReferenceURL: `https://osquery.readthedocs.io/en/stable/deployment/logging/`,
			Schema:       Differential{},
			NewParser:    parsers.AdapterFactory(&DifferentialParser{}),
		},
		pantherlog.EventType{
			Name:         TypeSnapshot,
			Description:  `Snapshot contains all the data included in OsQuery differential logs`,
			ReferenceURL: `https://osquery.readthedocs.io/en/stable/deployment/logging/`,
			Schema:       Snapshot{},
			NewParser:    parsers.AdapterFactory(&SnapshotParser{}),
		},
		pantherlog.EventType{
			Name:         TypeStatus,
			Description:  `Status is a diagnostic osquery log about the daemon.`,
			ReferenceURL: `https://osquery.readthedocs.io/en/stable/deployment/logging/`,
			Schema:       Status{},
			NewParser:    parsers.AdapterFactory(&StatusParser{}),
		},
	)
}
