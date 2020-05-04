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
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/jsontricks"
)

// const (
// 	PantherFieldPrefix = "p_"
// )

// var (
// 	// nolint:lll
// 	ipv4Regex  = regexp.MustCompile(`(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])*`)
// 	rowCounter RowID // number of rows generated in this lambda execution (used to generate p_row_id)
// )

// QuickParseJSON is a helper method for parsers that produce a single event from each JSON log line input.
func QuickParseJSON(event PantherEventer, src string) ([]*Result, error) {
	if err := jsoniter.UnmarshalFromString(src, event); err != nil {
		return nil, err
	}
	if err := ValidateStruct(event); err != nil {
		return nil, err
	}
	result, err := PackResult(event)
	if err != nil {
		return nil, err
	}
	return []*Result{result}, nil
}

// PackResults is a helper function for parsers to convert log events to PantherLogJSON.
// It validates, composes and serializes an appropriate struct based on the PantherEvent returned by the arguments.
func PackResults(events ...PantherEventer) ([]*Result, error) {
	results := make([]*Result, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		if err := ValidateStruct(event); err != nil {
			return nil, err
		}

		result, err := PackResult(event)
		if err != nil {
			return nil, errors.Errorf("Failed to pack event: %s", err)
		}
		results = append(results, result)
	}
	return results, nil
}

// PackResult is a helper function for parsers to convert a log event to Result.
// It detects the appropriate base pantherlog Meta struct to used from the prefix of the LogType.
// Custom panther logs that handle 'exotic' panther fields such as AWSPantherLog need to be
// registered in an `init()` block with `pantherlog.RegisterPrefix`
func PackResult(e PantherEventer) (*Result, error) {
	if e == nil {
		return nil, errors.Errorf("nil event")
	}

	event := e.PantherEvent()
	// Nil event is considered an error
	if event == nil {
		return nil, errors.Errorf("nil event")
	}

	meta, err := event.Meta()
	if err != nil {
		return nil, err
	}
	// Compose a JSON object of fields of meta and e
	// Order is important
	resultJSON, err := jsontricks.ConcatObjects(nil, e, meta)
	if err != nil {
		return nil, err
	}
	return &Result{
		LogType:   event.LogType,
		EventTime: event.Timestamp,
		JSON:      resultJSON,
	}, nil
}

// func NewPantherLogAt(logType string, eventTime, parseTime time.Time, fields ...PantherField) *PantherLog {
// 	if eventTime.IsZero() {
// 		eventTime = parseTime
// 	}
// 	rowID := rowCounter.NewRowID()
// 	p := PantherLog{
// 		PantherRowID:     &rowID,
// 		PantherLogType:   &logType,
// 		PantherEventTime: (*timestamp.RFC3339)(&eventTime),
// 		PantherParseTime: (*timestamp.RFC3339)(&parseTime),
// 	}
// 	p.ExtendPantherFields(fields...)
// 	return &p
// }

// func NewPantherLog(logType string, tm time.Time, fields ...PantherField) *PantherLog {
// 	return NewPantherLogAt(logType, tm, time.Now(), fields...)
// }

// // All log parsers should extend from this to get standardized fields (all prefixed with 'p_' as JSON for uniqueness)
// // NOTE: It is VERY important that fields are added to END of the structure to avoid needed to re-build existing Glue partitions.
// //       See https://github.com/awsdocs/amazon-athena-user-guide/blob/master/doc_source/updates-and-partitions.md
// // nolint(lll)
// type PantherLog struct {
// 	PantherLogType        *string            `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`
// 	PantherRowID          *string            `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"`
// 	PantherEventTime      *timestamp.RFC3339 `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`
// 	PantherParseTime      *timestamp.RFC3339 `json:"p_parse_time,omitempty" validate:"required" description:"Panther added standardize log parse time (UTC)"`
// 	PantherAnyIPAddresses SmallStringSet     `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`
// 	PantherAnyDomainNames SmallStringSet     `json:"p_any_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`
// 	PantherAnySHA1Hashes  SmallStringSet     `json:"p_any_sha1_hashes,omitempty" description:"Panther added field with collection of SHA1 hashes associated with the row"`
// 	PantherAnyMD5Hashes   SmallStringSet     `json:"p_any_md5_hashes,omitempty" description:"Panther added field with collection of MD5 hashes associated with the row"`
// }

// func (pl *PantherLog) ExtendPantherFields(fields ...PantherField) {
// 	for i := range fields {
// 		field := &fields[i]
// 		pl.InsertPantherField(field.Kind, field.Value)
// 	}
// }

// func (pl *PantherLog) AppendPantherFields(kind PantherFieldKind, values ...string) {
// 	for _, value := range values {
// 		pl.InsertPantherField(kind, value)
// 	}
// }
// func (pl *PantherLog) AppendPantherFieldsP(kind PantherFieldKind, values ...*string) {
// 	for _, value := range values {
// 		if value != nil {
// 			pl.InsertPantherField(kind, *value)
// 		}
// 	}
// }

// func (pl *PantherLog) InsertPantherField(kind PantherFieldKind, value string) {
// 	switch kind {
// 	case KindIPAddress:
// 		pl.PantherAnyIPAddresses.Insert(value)
// 	case KindMD5Hash:
// 		value = strings.TrimSpace(value)
// 		pl.PantherAnyMD5Hashes.Insert(value)
// 	case KindSHA1Hash:
// 		value = strings.TrimSpace(value)
// 		pl.PantherAnySHA1Hashes.Insert(value)
// 	case KindDomainName:
// 		value = strings.TrimSpace(value)
// 		pl.PantherAnyDomainNames.Insert(value)
// 	default:
// 		// PantherLog can only handle the above fields.
// 		// All other kind of fields should be handled by a different base struct (ie AWSPantherLog)
// 		// Prefer to fail hard here so tests can catch this ASAP
// 		panic(fmt.Sprintf("invalid panther field kind %d", kind))
// 	}
// }

// type SmallStringSet []string

// func (set SmallStringSet) MarshalJSON() ([]byte, error) {
// 	sort.Strings(set)
// 	return jsoniter.Marshal(([]string)(set))
// }
// func (set SmallStringSet) Contains(value string) bool {
// 	return indexOf(set, value) != -1
// }
// func (set *SmallStringSet) Insert(value string) {
// 	if value == "" {
// 		return
// 	}
// 	value = strings.TrimSpace(value)
// 	if value == "" {
// 		return
// 	}
// 	values := *set
// 	for _, v := range values {
// 		if v == value {
// 			return
// 		}
// 	}
// 	*set = append(values, value)
// }

// func (pl *PantherLog) Reset(logType string, eventTime *time.Time) {
// 	pl.ResetAt(logType, eventTime, time.Now())
// }

// func (pl *PantherLog) ResetAt(logType string, eventTime *time.Time, parseTime time.Time) {
// 	if eventTime == nil {
// 		eventTime = &parseTime
// 	}
// 	rowID := rowCounter.NewRowID()
// 	*pl = PantherLog{
// 		PantherRowID:     &rowID,
// 		PantherLogType:   &logType,
// 		PantherEventTime: (*timestamp.RFC3339)(eventTime),
// 		PantherParseTime: (*timestamp.RFC3339)(&parseTime),
// 	}
// }

// func (set *SmallStringSet) ExtendP(normalize func(string) string, values []*string) {
// 	if normalize == nil {
// 		normalize = strings.TrimSpace
// 	}
// 	for _, v := range values {
// 		if v != nil {
// 			set.Insert(normalize(*v))
// 		}
// 	}
// }

// func (set *SmallStringSet) Extend(normalize func(string) string, values []string) {
// 	if normalize == nil {
// 		normalize = strings.TrimSpace
// 	}
// 	for _, v := range values {
// 		set.Insert(normalize(v))
// 	}
// }

// func RepackJSON(event PantherEventer) (*Result, error) {
// 	return defaultRegistry.RepackJSON(event)
// }

// func MergeJSON(a, b interface{}) ([]byte, error) {
// 	// Compose the log event with the PantherLog struct to produce proper JSON
// 	w := strings.Builder{}
// 	w.Grow(1024)
// 	w.WriteByte('[')
// 	stream := jsoniter.ConfigFastest.BorrowStream(&w)
// 	stream.WriteVal(a)
// 	if err := stream.Error; err != nil {
// 		return nil, err
// 	}
// 	w.WriteByte(',')
// 	stream.WriteVal(b)
// 	if err := stream.Error; err != nil {
// 		return nil, err
// 	}
// 	w.WriteByte(']')
// 	jsoniter.ConfigFastest.ReturnStream(stream)
// 	outJSON := gjson.Get(w.String(), `@join:{"preserve":true}`).Raw
// 	return []byte(outJSON), nil
// }

// func (r *Registry) RepackJSON(event PantherEventer) (*Result, error) {
// 	if event == nil {
// 		return nil, errors.Errorf("nil event")
// 	}

// 	e := event.PantherEvent()

// 	// Nil event is considered an error
// 	if e == nil {
// 		return nil, errors.Errorf("nil event")
// 	}

// 	logType := r.Get(e.LogType)
// 	if logType == nil {
// 		return nil, errors.Errorf("unregistered log type %q", e.LogType)
// 	}
// 	factory := logType.PantherLog
// 	if factory == nil {
// 		factory = defaultPantherLogFactory
// 	}
// 	p := factory(e.LogType, e.Timestamp, e.Fields...)

// 	// Validate factory output so each PantherLog struct can define it's own validation rules
// 	if err := Validator.Struct(p); err != nil {
// 		return nil, err
// 	}

// 	outJSON, err := MergeJSON(event, p)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &Result{
// 		LogType:   e.LogType,
// 		EventTime: e.Timestamp,
// 		JSON:      outJSON,
// 	}, nil
// }
