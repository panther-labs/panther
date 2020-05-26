package pantherlog

import (
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

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

// FieldPrefix is the prefix for field names injected by panther to log events.
const FieldPrefix = "p_"

// Meta contains the default fields that panther adds to a log event.
// It is used to convert log events to Result.
// NOTE: It is VERY important that fields are added to END of the structure to avoid needed to re-build existing Glue partitions.
//       See https://github.com/awsdocs/amazon-athena-user-guide/blob/master/doc_source/updates-and-partitions.md
// nolint(lll)
type Meta struct {
	PantherLogType        string            `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`
	PantherRowID          string            `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"`
	PantherEventTime      timestamp.RFC3339 `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`
	PantherParseTime      timestamp.RFC3339 `json:"p_parse_time,omitempty" validate:"required" description:"Panther added standardize log parse time (UTC)"`
	PantherAnyIPAddresses []string          `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`
	PantherAnyDomainNames []string          `json:"p_any_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`
	PantherAnySHA1Hashes  []string          `json:"p_any_sha1_hashes,omitempty" description:"Panther added field with collection of SHA1 hashes associated with the row"`
	PantherAnyMD5Hashes   []string          `json:"p_any_md5_hashes,omitempty" description:"Panther added field with collection of MD5 hashes associated with the row"`
}

// NewMeta creates a new Meta from an event.
// It returns a struct directly to be easily used in MetaFactory functions for
// structs that embed the default `Meta` struct
func NewMeta(event *Event) Meta {
	if event == nil {
		return Meta{}
	}
	parseTime := time.Now()
	eventTime := event.Timestamp
	if eventTime.IsZero() {
		eventTime = parseTime
	}
	// Convert times to UTC
	eventTime = eventTime.UTC()
	parseTime = parseTime.UTC()
	rowID := NextRowID()
	return Meta{
		PantherRowID:          rowID,
		PantherLogType:        event.LogType,
		PantherParseTime:      (timestamp.RFC3339)(parseTime),
		PantherEventTime:      (timestamp.RFC3339)(event.Timestamp),
		PantherAnyDomainNames: event.Values(KindDomainName),
		PantherAnyIPAddresses: event.Values(KindIPAddress),
		PantherAnySHA1Hashes:  event.Values(KindSHA1Hash),
		PantherAnyMD5Hashes:   event.Values(KindMD5Hash),
	}
}

// MetaFactory converts an event to a struct containing panther meta info.
// Meta returned is considered valid, any validation on the meta struct should happen here.
type MetaFactory func(e *Event) (interface{}, error)

var metaRegistry = map[string]MetaFactory{}

// MustRegisterMetaPrefix registers a custom MetaFactory for a log type prefix.
func MustRegisterMetaPrefix(prefix string, fac MetaFactory) {
	if fac == nil {
		panic(errors.New("nil factory"))
	}
	if _, duplicate := metaRegistry[prefix]; duplicate {
		// use Errorf for stack trace
		panic(errors.Errorf("duplicate event transformer %q", prefix))
	}
	metaRegistry[prefix] = fac
}

var valid = validator.New()

func defaultMetaFactory(event *Event) (interface{}, error) {
	if event == nil {
		return nil, errors.Errorf("nil event")
	}
	meta := NewMeta(event)
	if err := valid.Struct(meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// Meta uses the logType prefix to construct a value containing all panther meta fields and info.
// If a custom factory is registered for the event.LogType it is used to create the value.
// Otherwise the default Meta struct is returned.
// A custom MetaFactory can be registered for a log type prefix with `RegisterPrefixMeta`.
func (e *Event) Meta() (interface{}, error) {
	if e == nil {
		return nil, errors.Errorf("nil event")
	}
	prefix := logTypePrefix(e.LogType)
	factory := metaRegistry[prefix]
	if factory == nil {
		factory = defaultMetaFactory
	}
	return factory(e)
}

func logTypePrefix(s string) string {
	const prefixDelimiter = '.'
	if pos := strings.IndexByte(s, prefixDelimiter); 0 <= pos && pos < len(s) {
		return s[:pos]
	}
	return s
}
