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
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/anystring"
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
	event interface{} // points to event that encapsulates this  as interface{} so we can serialize full event.

	//  required
	PantherLogType   *string            `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`
	PantherRowID     *string            `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"`
	PantherEventTime *timestamp.RFC3339 `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`
	PantherParseTime *timestamp.RFC3339 `json:"p_parse_time,omitempty" validate:"required" description:"Panther added standardize log parse time (UTC)"`

	// optional (any)
	PantherAnyIPAddresses  PantherAnyString `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`
	PantherAnyDomainNames  PantherAnyString `json:"p_any_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`
	PantherAnySHA1Hashes   PantherAnyString `json:"p_any_sha1_hashes,omitempty" description:"Panther added field with collection of SHA1 hashes associated with the row"`
	PantherAnyMD5Hashes    PantherAnyString `json:"p_any_md5_hashes,omitempty" description:"Panther added field with collection of MD5 hashes associated with the row"`
	PantherAnySHA256Hashes PantherAnyString `json:"p_any_sha256_hashes,omitempty" description:"Panther added field with collection of SHA256 hashes of any algorithm associated with the row"`
}

type PantherAnyString = anystring.Set

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
		pl.PantherAnyIPAddresses.Add(value)
		return true
	}
	return false
}

func (pl *PantherLog) AppendAnyDomainNamePtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.PantherAnyDomainNames.Add(*value)
		}
	}
}

func (pl *PantherLog) AppendAnyDomainNames(values ...string) {
	AppendAnyString(&pl.PantherAnyDomainNames, values...)
}

func (pl *PantherLog) AppendAnySHA1HashPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.PantherAnySHA1Hashes.Add(*value)
		}
	}
}

func (pl *PantherLog) AppendAnySHA1Hashes(values ...string) {
	AppendAnyString(&pl.PantherAnySHA1Hashes, values...)
}

func (pl *PantherLog) AppendAnyMD5HashPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.PantherAnyMD5Hashes.Add(*value)
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
			pl.PantherAnySHA256Hashes.Add(*value)
		}
	}
}

func AppendAnyString(any *PantherAnyString, values ...string) {
	anystring.Append(any, values...)
}

// Result converts a PantherLog to Result
// NOTE: Currently in this file to help with review
func (pl *PantherLog) Result() (*Result, error) {
	event := pl.Event()
	if event == nil {
		return nil, errors.New("nil event")
	}
	if pl.PantherLogType == nil {
		return nil, errors.New("nil log type")
	}
	if pl.PantherEventTime == nil {
		return nil, errors.New("nil event time")
	}
	tm := ((*time.Time)(pl.PantherEventTime)).UTC()
	// Use custom JSON marshaler to rewrite fields
	data, err := JSON.Marshal(event)
	if err != nil {
		return nil, err
	}
	return &Result{
		LogType:   *pl.PantherLogType,
		EventTime: tm,
		JSON:      data,
	}, nil
}

// Results converts a PantherLog to a slice of results
// NOTE: Currently in this file to help with review
func (pl *PantherLog) Results() ([]*Result, error) {
	result, err := pl.Result()
	if err != nil {
		return nil, err
	}
	return []*Result{result}, nil
}

func ToResults(logs []*PantherLog, err error) ([]*Result, error) {
	if err != nil {
		return nil, err
	}
	results := make([]*Result, len(logs))
	for i := range results {
		result, err := logs[i].Result()
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}
