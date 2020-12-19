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
	"net"
	"regexp"
	"sort"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/rowid"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
	"github.com/panther-labs/panther/pkg/stringset"
	"github.com/panther-labs/panther/pkg/unbox"
)

const (
	PantherFieldPrefix = "p_"
)

var (
	ipv4Regex  = regexp.MustCompile(`(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])*`)
	rowCounter rowid.RowID // number of rows generated in this lambda execution (used to generate p_row_id)
)

// All log parsers should extend from this to get standardized fields (all prefixed with 'p_' as JSON for uniqueness)
// NOTE: It is VERY important that fields are added to END of the structure to avoid needed to re-build existing Glue partitions.
//       See https://github.com/awsdocs/amazon-athena-user-guide/blob/master/doc_source/updates-and-partitions.md
// nolint(lll)
type PantherLog struct {
	event interface{} // points to event that encapsulates this  as interface{} so we can serialize full event.

	//  required
	PantherLogType     *string            `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`
	PantherRowID       *string            `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"`
	PantherEventTime   *timestamp.RFC3339 `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`
	PantherParseTime   *timestamp.RFC3339 `json:"p_parse_time,omitempty" validate:"required" description:"Panther added standardize log parse time (UTC)"`
	PantherSourceID    *string            `json:"p_source_id,omitempty" description:"Panther added field with the source id"`
	PantherSourceLabel *string            `json:"p_source_label,omitempty" description:"Panther added field with the source label"`

	// optional (any)
	PantherAnyIPAddresses  PantherAnyString `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`
	PantherAnyDomainNames  PantherAnyString `json:"p_any_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`
	PantherAnySHA1Hashes   PantherAnyString `json:"p_any_sha1_hashes,omitempty" description:"Panther added field with collection of SHA1 hashes associated with the row"`
	PantherAnyMD5Hashes    PantherAnyString `json:"p_any_md5_hashes,omitempty" description:"Panther added field with collection of MD5 hashes associated with the row"`
	PantherAnySHA256Hashes PantherAnyString `json:"p_any_sha256_hashes,omitempty" description:"Panther added field with collection of SHA256 hashes of any algorithm associated with the row"`
}

type PantherAnyString []string

func (any PantherAnyString) MarshalJSON() ([]byte, error) {
	// The safe way to do this is to clone.
	// MarshalJSON is not supposed to be altering the value.
	// If we used stringset.Dedup + sort.Strings we could corrupt the input slice.
	values := stringset.New(any...)
	sort.Strings(values)
	return jsoniter.Marshal(values)
}

// Event returns event data, used when composed
func (pl *PantherLog) Event() interface{} {
	return pl.event
}

// SetEvent set  event data, used for testing
func (pl *PantherLog) SetEvent(event interface{}) {
	pl.event = event
}

// Log returns pointer to self, used when composed
func (pl *PantherLog) Log() *PantherLog {
	return pl
}

// Logs returns a slice with pointer to self, used when composed
func (pl *PantherLog) Logs() []*PantherLog {
	return []*PantherLog{pl}
}

func (pl *PantherLog) SetCoreFields(logType string, eventTime *timestamp.RFC3339, event interface{}) {
	parseTime := timestamp.Now()

	if eventTime == nil {
		eventTime = &parseTime
	}
	rowID := rowCounter.NewRowID()
	pl.event = event
	pl.PantherRowID = &rowID
	pl.PantherLogType = &logType
	pl.PantherEventTime = eventTime
	pl.PantherParseTime = &parseTime
}

type PantherSourceSetter interface {
	SetPantherSource(id, label string)
}

var _ PantherSourceSetter = (*PantherLog)(nil)

func (pl *PantherLog) SetPantherSource(id, label string) {
	pl.PantherSourceLabel = box.NonEmpty(label)
	pl.PantherSourceID = box.NonEmpty(id)
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
		AppendAnyString(&pl.PantherAnyIPAddresses, value)
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
	AppendAnyString(&pl.PantherAnyDomainNames, values...)
}

func (pl *PantherLog) AppendAnySHA1HashPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnySHA1Hashes(*value)
		}
	}
}

func (pl *PantherLog) AppendAnySHA1Hashes(values ...string) {
	AppendAnyString(&pl.PantherAnySHA1Hashes, values...)
}

func (pl *PantherLog) AppendAnyMD5HashPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnyMD5Hashes(*value)
		}
	}
}

func (pl *PantherLog) AppendAnyMD5Hashes(values ...string) {
	AppendAnyString(&pl.PantherAnyMD5Hashes, values...)
}

func (pl *PantherLog) AppendAnySHA256Hashes(values ...string) {
	AppendAnyString(&pl.PantherAnySHA256Hashes, values...)
}

func (pl *PantherLog) AppendAnySHA256HashesPtr(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnySHA256Hashes(*value)
		}
	}
}

func AppendAnyString(any *PantherAnyString, values ...string) {
	// add new if not present
	for _, v := range values {
		if v == "" { // ignore empty strings
			continue
		}
		*any = stringset.Append(*any, v)
	}
}

// Result converts a PantherLog to Result
func (pl *PantherLog) Result() *Result {
	event := pl.Event()
	parseTime := pl.PantherParseTime
	if parseTime == nil {
		now := time.Now()
		parseTime = (*timestamp.RFC3339)(&now)
	}
	eventTime := pl.PantherEventTime
	if eventTime == nil {
		eventTime = parseTime
	}
	return &pantherlog.Result{
		// Use EventIncludesPantherFields so that our custom ValEncoder for Result knows to not duplicate Panther added fields
		EventIncludesPantherFields: true,
		Event:                      event,
		CoreFields: pantherlog.CoreFields{
			PantherLogType:     unbox.String(pl.PantherLogType),
			PantherRowID:       unbox.String(pl.PantherRowID),
			PantherParseTime:   ((*time.Time)(parseTime)).UTC(),
			PantherEventTime:   ((*time.Time)(eventTime)).UTC(),
			PantherSourceID:    unbox.String(pl.PantherSourceID),
			PantherSourceLabel: unbox.String(pl.PantherSourceLabel),
		},
	}
}

// Results converts a PantherLog to a slice of results
func (pl *PantherLog) Results() ([]*Result, error) {
	return []*Result{pl.Result()}, nil
}

func ToResults(logs []*PantherLog, err error) ([]*Result, error) {
	if err != nil {
		return nil, err
	}
	results := make([]*Result, len(logs))
	for i := range results {
		result := logs[i].Result()
		results[i] = result
	}
	return results, nil
}
