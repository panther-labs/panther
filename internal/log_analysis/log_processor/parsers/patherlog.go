package parsers

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
	"sort"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const (
	PantherFieldPrefix = "p_"
)

var (
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

	// optional (any)
	PantherAnyIPAddresses *PantherAnyString `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`
	PantherAnyDomainNames *PantherAnyString `json:"p_any_ip_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`
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

func (pl *PantherLog) SetCoreFieldsPtr(logType string, eventTime *timestamp.RFC3339) {
	if eventTime != nil {
		pl.SetCoreFields(logType, *eventTime)
	}
}

func (pl *PantherLog) SetCoreFields(logType string, eventTime timestamp.RFC3339) {
	pl.PantherLogType = &logType
	rowID := rowCounter.NewRowID()
	pl.PantherRowID = &rowID
	pl.PantherEventTime = &eventTime
}

func (pl *PantherLog) AppendAnyIPAddressPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnyIPAddresses(*value)
		}
	}
}

func (pl *PantherLog) AppendAnyIPAddresses(values ...string) {
	if pl.PantherAnyIPAddresses == nil { // lazy create
		pl.PantherAnyIPAddresses = NewPantherAnyString()
	}
	AppendAnyString(pl.PantherAnyIPAddresses, values...)
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
