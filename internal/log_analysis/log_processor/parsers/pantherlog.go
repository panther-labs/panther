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
	"net"
	"regexp"
	"sort"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const (
	PantherFieldPrefix = "p_"
)

var (
	ipv4Regex  = regexp.MustCompile(`(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])*`)
	rowCounter RowID // number of rows generated in this lambda execution (used to generate p_row_id)
)

// All log parsers should extend from this to get standardized fields (all prefixed with 'p_' as JSON for uniqueness)
// NOTE: It is VERY important that fields are added to END of the structure to avoid needed to re-build existing Glue partitions.
//       See https://github.com/awsdocs/amazon-athena-user-guide/blob/master/doc_source/updates-and-partitions.md
// nolint(lll)
type PantherLog struct {
	// event interface{} // points to event that encapsulates this  as interface{} so we can serialize full event.

	//  required
	PantherLogType   *string            `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`
	PantherRowID     *string            `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"`
	PantherEventTime *timestamp.RFC3339 `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`
	PantherParseTime *timestamp.RFC3339 `json:"p_parse_time,omitempty" validate:"required" description:"Panther added standardize log parse time (UTC)"`

	// optional (any)
	PantherAnyIPAddresses *PantherAnyString `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`
	PantherAnyDomainNames *PantherAnyString `json:"p_any_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`
	PantherAnySHA1Hashes  *PantherAnyString `json:"p_any_sha1_hashes,omitempty" description:"Panther added field with collection of SHA1 hashes associated with the row"`
	PantherAnyMD5Hashes   *PantherAnyString `json:"p_any_md5_hashes,omitempty" description:"Panther added field with collection of MD5 hashes associated with the row"`
}

type PantherLogJSON struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

// var (
// 	typPantherLog = reflect.TypeOf(PantherLog{})
// )

func NewPantherLog(logType string, tm time.Time, fields ...PantherField) *PantherLog {
	now := time.Now()
	if tm.IsZero() {
		tm = now
	}
	rowID := rowCounter.NewRowID()
	p := PantherLog{
		PantherRowID:     &rowID,
		PantherLogType:   &logType,
		PantherEventTime: (*timestamp.RFC3339)(&tm),
		PantherParseTime: (*timestamp.RFC3339)(&now),
	}
	p.SetFields(fields...)
	return &p
}

type PantherAnyString struct { // needed to declare as struct (rather than map) for CF generation
	set map[string]struct{} // map is used for uniqueness, serializes as JSON list
}

func NewPantherAnyString() *PantherAnyString {
	return &PantherAnyString{
		set: make(map[string]struct{}),
	}
}

func (any *PantherAnyString) MarshalJSON() ([]byte, error) {
	if any != nil { // copy to slice
		values := make([]string, len(any.set))
		i := 0
		for k := range any.set {
			values[i] = k
			i++
		}
		sort.Strings(values) // sort for consistency and to improve compression when stored
		return jsoniter.Marshal(values)
	}
	return []byte{}, nil
}

func (any *PantherAnyString) UnmarshalJSON(jsonBytes []byte) error {
	var values []string
	err := jsoniter.Unmarshal(jsonBytes, &values)
	if err != nil {
		return err
	}
	any.set = make(map[string]struct{}, len(values))
	for _, entry := range values {
		any.set[entry] = struct{}{}
	}
	return nil
}

// // Event returns event data, used when composed
// func (pl *PantherLog) Event() interface{} {
// 	return pl.event
// }

// // SetEvent set  event data, used for testing
// func (pl *PantherLog) SetEvent(event interface{}) {
// 	if e, ok := event.(PantherEventer); ok {
// 		typ, ts, fields := e.PantherEvent()
// 		pl.SetCoreFields(typ, (*timestamp.RFC3339)(&ts), event)
// 		pl.SetFields(fields...)
// 	} else {
// 		pl.event = event
// 	}
// }

// // Log returns pointer to self, used when composed
// func (pl *PantherLog) Log() *PantherLogJSON {
// 	data, _ := jsoniter.Marshal(pl.Event())
// 	return &PantherLogJSON{
// 		LogType:   *pl.PantherLogType,
// 		EventTime: pl.PantherEventTime.UTC(),
// 		JSON:      data,
// 	}
// }

// // Logs returns a slice with pointer to self, used when composed
// func (pl *PantherLog) Logs() []*PantherLogJSON {
// 	return []*PantherLogJSON{pl.Log()}
// }

type PantherFields struct {
	Fields []PantherField
}

func (pfs *PantherFields) AppendIP(addr string) {
	if net.ParseIP(addr) != nil {
		pfs.Fields = append(pfs.Fields, KindIPAddress.Field(addr))
	}
}

func (pfs *PantherFields) Append(kind PantherFieldKind, values ...string) {
	for _, value := range values {
		pfs.Fields = append(pfs.Fields, kind.Field(value))
	}
}

// func (pfs *PantherFields) AppendP(kind PantherFieldKind, values ...*string) {
// 	for _, value := range values {
// 		pfs.Fields = append(pfs.Fields, kind.FieldP(value))
// 	}
// }

func (pl *PantherLog) SetFields(fields ...PantherField) {
	for i := range fields {
		field := &fields[i]
		if field.Value == "" {
			continue
		}
		switch field.Kind {
		case KindIPAddress:
			pl.AppendAnyIPAddress(field.Value)
		case KindMD5Hash:
			pl.AppendAnyMD5Hashes(field.Value)
		case KindSHA1Hash:
			pl.AppendAnySHA1Hashes(field.Value)
		case KindDomainName:
			pl.AppendAnyDomainNames(field.Value)
		}
	}
}

// func PantherLogEvent(event PantherEventer) PantherLog {
// 	parseTime := timestamp.Now()
// 	logType, eventTime, fields := event.PantherEvent()
// 	if eventTime.IsZero() {
// 		eventTime = time.Time(parseTime)
// 	}
// 	rowID := rowCounter.NewRowID()
// 	pl := PantherLog{
// 		PantherRowID:     &rowID,
// 		PantherLogType:   &logType,
// 		PantherEventTime: (*timestamp.RFC3339)(&eventTime),
// 		PantherParseTime: &parseTime,
// 	}
// 	pl.SetFields(fields...)
// 	return pl
// }

func (pl *PantherLog) SetCoreFields(logType string, eventTime *timestamp.RFC3339, event interface{}) {
	parseTime := timestamp.Now()

	if eventTime == nil {
		eventTime = &parseTime
	}
	rowID := rowCounter.NewRowID()
	// pl.event = event
	pl.PantherRowID = &rowID
	pl.PantherLogType = &logType
	pl.PantherEventTime = eventTime
	pl.PantherParseTime = &parseTime
}

// AppendAnyIPAddressPtr returns true if the IP address was successfully appended,
// otherwise false if the value was not an IP
func (pl *PantherLog) AppendAnyIPAddressPtr(value *string) bool {
	if value == nil {
		return false
	}
	return pl.AppendAnyIPAddress(*value)
}

// AppendAnyIPAddressInFieldPtr makes sure the value passed is not nil before
// passing into AppendAnyIPAddressInField
func (pl *PantherLog) AppendAnyIPAddressInFieldPtr(value *string) bool {
	if value == nil {
		return false
	}
	return pl.AppendAnyIPAddressInField(*value)
}

// AppendAnyIPAddressInField extracts all IPs from the value using a regexp
func (pl *PantherLog) AppendAnyIPAddressInField(value string) bool {
	matchedIPs := ipv4Regex.FindAllString(value, -1)
	if len(matchedIPs) == 0 {
		return false
	}
	for _, match := range matchedIPs {
		if !pl.AppendAnyIPAddress(match) {
			return false
		}
	}
	return true
}

func (pl *PantherLog) AppendAnyIPAddress(value string) bool {
	if net.ParseIP(value) != nil {
		if pl.PantherAnyIPAddresses == nil { // lazy create
			pl.PantherAnyIPAddresses = NewPantherAnyString()
		}
		AppendAnyString(pl.PantherAnyIPAddresses, value)
		return true
	}
	return false
}

func (pl *PantherLog) AppendAnyDomainNamePtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnyDomainNames(*value)
		}
	}
}

func (pl *PantherLog) AppendAnyDomainNames(values ...string) {
	if pl.PantherAnyDomainNames == nil { // lazy create
		pl.PantherAnyDomainNames = NewPantherAnyString()
	}
	AppendAnyString(pl.PantherAnyDomainNames, values...)
}

func (pl *PantherLog) AppendAnySHA1HashPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnySHA1Hashes(*value)
		}
	}
}

func (pl *PantherLog) AppendAnySHA1Hashes(values ...string) {
	if pl.PantherAnySHA1Hashes == nil { // lazy create
		pl.PantherAnySHA1Hashes = NewPantherAnyString()
	}
	AppendAnyString(pl.PantherAnySHA1Hashes, values...)
}

func (pl *PantherLog) AppendAnyMD5HashPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnyMD5Hashes(*value)
		}
	}
}

func (pl *PantherLog) AppendAnyMD5Hashes(values ...string) {
	if pl.PantherAnyMD5Hashes == nil { // lazy create
		pl.PantherAnyMD5Hashes = NewPantherAnyString()
	}
	AppendAnyString(pl.PantherAnyMD5Hashes, values...)
}

func AppendAnyString(any *PantherAnyString, values ...string) {
	// add new if not present
	for _, v := range values {
		if v == "" { // ignore empty strings
			continue
		}
		if _, exists := any.set[v]; exists {
			continue
		}
		any.set[v] = struct{}{} // new
	}
}

func QuickParseJSON(event PantherEventer, src string) ([]*PantherLogJSON, error) {
	if err := jsoniter.UnmarshalFromString(src, event); err != nil {
		return nil, err
	}
	if err := Validator.Struct(event); err != nil {
		return nil, err
	}
	return PackEvents(event)
}

// func PackEventsCustom(events ...PantherEventer) ([]*PantherLogJSON, error) {
// 	packedEvents := make([]*PantherLogJSON, 0, len(events))
// 	for _, event := range events {
// 		if event == nil {
// 			continue
// 		}
// 		packed, err := RepackJSON(event)
// 		if err != nil {
// 			return nil, fmt.Errorf("Failed to pack event: %s", err)
// 		}
// 		packedEvents = append(packedEvents, packed)
// 	}
// 	return packedEvents, nil
// }
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
			return nil, fmt.Errorf("Failed to pack event: %s", err)
		}
		packedEvents = append(packedEvents, packed)
	}
	return packedEvents, nil
}

func RepackJSON(event PantherEventer) (*PantherLogJSON, error) {
	if event == nil {
		return nil, fmt.Errorf("nil event")
	}
	e := event.PantherEvent()
	if e == nil {
		return nil, fmt.Errorf("nil event")
	}
	prefix := LogTypePrefix(e.LogType)
	factory, ok := pantherLogRegistry[prefix]
	if !ok {
		factory = pantherLogRegistry["default"]
	}
	p := factory(e.LogType, e.Timestamp, e.Fields...)
	if err := Validator.Struct(p); err != nil {
		return nil, err
	}
	tmp, err := ComposeStruct(event, p)
	if err != nil {
		return nil, err
	}
	data, err := jsoniter.Marshal(tmp.Interface())
	if err != nil {
		return nil, err
	}
	return &PantherLogJSON{
		LogType:   e.LogType,
		EventTime: e.Timestamp,
		JSON:      data,
	}, nil
	// pJSON, err := pEvent.JSON() if err != nil {
	// 	return nil, err
	// }

	// // eventValue := reflect.Indirect(reflect.ValueOf(event))
	// // if eventValue.Kind() != reflect.Struct {
	// // 	return nil, fmt.Errorf("Invalid event value %s", eventValue.Type())
	// // }
	// prefix := LogTypePrefix(p)
	// factory, ok := pantherLogRegistry[prefix]
	// if !ok {
	// 	factory = pantherLogRegistry["default"]
	// }
	// p := factory(logType, tm, pantherFields...)
	// if err := Validator.Struct(p); err != nil {
	// 	return nil, err
	// }
	// tmp, err := ComposeStruct(event, p)

	// // fields := []reflect.StructField{
	// // 	{
	// // 		Name:      eventValue.Type().Name(),
	// // 		Anonymous: true,
	// // 		Type:      eventValue.Type(),
	// // 		Index:     []int{0},
	// // 	},
	// // 	{
	// // 		Name:      "PantherLog",
	// // 		Anonymous: true,
	// // 		Index:     []int{1},
	// // 		Type:      typPantherLog,
	// // 	},
	// // }
	// // typComposedEvent := reflect.StructOf(fields)
	// // composedEvent := reflect.New(typComposedEvent)
	// // composedEvent.Elem().Field(0).Set(eventValue)
	// // composedEvent.Elem().Field(1).Set(reflect.ValueOf(p))
	// // x := composedEvent.Interface()
	// // data, err := json.Marshal(x)
	// data, err := jsoniter.Marshal(tmp.Interface())
	// if err != nil {
	// 	return nil, err
	// }
	// return &PantherLogJSON{
	// 	LogType:   logType,
	// 	EventTime: tm,
	// 	JSON:      data,
	// }, nil

}
