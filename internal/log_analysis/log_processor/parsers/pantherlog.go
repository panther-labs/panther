package parsers

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
	"sort"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const (
	PantherFieldPrefix = "p_"
)

var (
	// nolint:lll
	ipv4Regex  = regexp.MustCompile(`(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])*`)
	rowCounter RowID // number of rows generated in this lambda execution (used to generate p_row_id)
)

// All log parsers should extend from this to get standardized fields (all prefixed with 'p_' as JSON for uniqueness)
// NOTE: It is VERY important that fields are added to END of the structure to avoid needed to re-build existing Glue partitions.
//       See https://github.com/awsdocs/amazon-athena-user-guide/blob/master/doc_source/updates-and-partitions.md
// nolint(lll)
type PantherLog struct {
	//  required
	PantherLogType   *string            `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`
	PantherRowID     *string            `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"`
	PantherEventTime *timestamp.RFC3339 `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`
	PantherParseTime *timestamp.RFC3339 `json:"p_parse_time,omitempty" validate:"required" description:"Panther added standardize log parse time (UTC)"`

	PantherLogFields
}

// nolint:lll
type PantherLogFields struct {
	// optional (any)
	PantherAnyIPAddresses SmallStringSet `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`
	PantherAnyDomainNames SmallStringSet `json:"p_any_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`
	PantherAnySHA1Hashes  SmallStringSet `json:"p_any_sha1_hashes,omitempty" description:"Panther added field with collection of SHA1 hashes associated with the row"`
	PantherAnyMD5Hashes   SmallStringSet `json:"p_any_md5_hashes,omitempty" description:"Panther added field with collection of MD5 hashes associated with the row"`
}

func (fields *PantherLogFields) ExtendPantherFields(ext ...PantherField) {
	for i := range ext {
		field := &ext[i]
		fields.InsertPantherField(field.Kind, field.Value)
	}
}
func (fields *PantherLogFields) AppendPantherField(kind PantherFieldKind, values ...string) {
	for _, value := range values {
		fields.InsertPantherField(kind, value)
	}
}
func (fields *PantherLogFields) AppendPantherFieldP(kind PantherFieldKind, values ...*string) {
	for _, value := range values {
		if value != nil {
			fields.InsertPantherField(kind, *value)
		}
	}
}

func (fields *PantherLogFields) InsertPantherField(kind PantherFieldKind, value string) {
	switch kind {
	case KindIPAddress:

		// value = NormalizeIPAddress(value)
		fields.PantherAnyIPAddresses.Insert(value)
	case KindMD5Hash:
		value = strings.TrimSpace(value)
		fields.PantherAnyMD5Hashes.Insert(value)
	case KindSHA1Hash:
		value = strings.TrimSpace(value)
		fields.PantherAnySHA1Hashes.Insert(value)
	case KindDomainName:
		value = strings.TrimSpace(value)
		fields.PantherAnyDomainNames.Insert(value)
	// case KindHostname:
	// 	if value := NormalizeIPAddress(value); value != "" {
	// 		fields.PantherAnyIPAddresses.Insert(value)
	// 	} else {
	// 		value = strings.TrimSpace(value)
	// 		fields.PantherAnyDomainNames.Insert(value)
	// 	}
	default:
		// PantherLogFields can only handle the above fields.
		// All other kind of fields should be handled by a different base struct (ie AWSPantherLog)
		// Prefer to fail hard here so tests can catch this ASAP
		panic(fmt.Sprintf("invalid panther field kind %d", kind))
	}
}

type SmallStringSet []string

func (set SmallStringSet) MarshalJSON() ([]byte, error) {
	sort.Strings(set)
	return jsoniter.Marshal(([]string)(set))
}
func (set SmallStringSet) Contains(value string) bool {
	return indexOf(set, value) != -1
}
func (set *SmallStringSet) Insert(value string) {
	if value == "" {
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	values := *set
	for _, v := range values {
		if v == value {
			return
		}
	}
	*set = append(values, value)
}

func (p *PantherLog) Reset(logType string, eventTime *time.Time) {
	p.ResetAt(logType, eventTime, time.Now())
}
func (p *PantherLog) ResetAt(logType string, eventTime *time.Time, parseTime time.Time) {
	if eventTime == nil {
		eventTime = &parseTime
	}
	rowID := rowCounter.NewRowID()
	*p = PantherLog{
		PantherRowID:     &rowID,
		PantherLogType:   &logType,
		PantherEventTime: (*timestamp.RFC3339)(eventTime),
		PantherParseTime: (*timestamp.RFC3339)(&parseTime),
	}
}

func (set *SmallStringSet) ExtendP(normalize func(string) string, values []*string) {
	if normalize == nil {
		normalize = strings.TrimSpace
	}
	for _, v := range values {
		if v != nil {
			set.Insert(normalize(*v))
		}
	}
}

func (set *SmallStringSet) Extend(normalize func(string) string, values []string) {
	if normalize == nil {
		normalize = strings.TrimSpace
	}
	for _, v := range values {
		set.Insert(normalize(v))
	}
}

type PantherLogJSON struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

func NewPantherLogAt(logType string, eventTime, parseTime time.Time, fields ...PantherField) *PantherLog {
	if eventTime.IsZero() {
		eventTime = parseTime
	}
	rowID := rowCounter.NewRowID()
	p := PantherLog{
		PantherRowID:     &rowID,
		PantherLogType:   &logType,
		PantherEventTime: (*timestamp.RFC3339)(&eventTime),
		PantherParseTime: (*timestamp.RFC3339)(&parseTime),
	}
	p.ExtendPantherFields(fields...)
	return &p
}

func NewPantherLog(logType string, tm time.Time, fields ...PantherField) *PantherLog {
	return NewPantherLogAt(logType, tm, time.Now(), fields...)
}

// QuickParseJSON is a helper method for parsers that produce a single event from each JSON log line input.
func QuickParseJSON(event PantherEventer, src string) ([]*PantherLogJSON, error) {
	if err := jsoniter.UnmarshalFromString(src, event); err != nil {
		return nil, err
	}
	return PackEvents(event)
}

// PackEvents is a helper function for parsers to convert log events to PantherLogJSON.
// It validates, composes and serializes an appropriate struct based on the PantherEvent returned by the arguments.
func PackEvents(events ...PantherEventer) ([]*PantherLogJSON, error) {
	packedEvents := make([]*PantherLogJSON, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		if err := Validator.Struct(event); err != nil {
			return nil, err
		}
		packed, err := RepackJSON(event)
		if err != nil {
			return nil, errors.Errorf("Failed to pack event: %s", err)
		}
		packedEvents = append(packedEvents, packed)
	}
	return packedEvents, nil
}

// RepackJSON is a helper function for parsers to convert a log event to PantherLogJSON.
// It detects the appropriate base PantherLog struct to used from the prefix of the LogType.
// Custom panther logs that handle 'exotic' panther fields such as AWSPantherLog need to be
// registered in an `init()` block with `RegisterPantherLogPrefix`
func RepackJSON(event PantherEventer) (*PantherLogJSON, error) {
	if event == nil {
		return nil, errors.Errorf("nil event")
	}

	e := event.PantherEvent()

	// Nil event is considered an error
	if e == nil {
		return nil, errors.Errorf("nil event")
	}

	// Extract the log type prefix to find the appropriate PantherLog for this log event.
	prefix := LogTypePrefix(e.LogType)

	factory, ok := pantherLogRegistry[prefix]
	if !ok {
		// Fall back to default panther log factory (NewPantherLog)
		factory = pantherLogRegistry["default"]
	}

	p := factory(e.LogType, e.Timestamp, e.Fields...)

	// Validate factory output so each PantherLog struct can define it's own validation rules
	if err := Validator.Struct(p); err != nil {
		return nil, err
	}
	// Compose the log event with the PantherLog struct to produce proper JSON
	tmp, err := ComposeStruct(event, p)
	if err != nil {
		return nil, err
	}
	// The JSON returned here will have the original log event fields plus all `p_` prefixed
	// fields defined in the PantherLog returned from the factory
	data, err := jsoniter.Marshal(tmp.Interface())
	if err != nil {
		return nil, err
	}
	return &PantherLogJSON{
		LogType:   e.LogType,
		EventTime: e.Timestamp,
		JSON:      data,
	}, nil
}
