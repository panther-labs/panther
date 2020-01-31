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

var (
	rowCounter RowID // number of rows generated in this lambda execution (used to generate p_row_id)
)

// All log parsers should extend from this to get standardized fields (all prefixed with 'p_' as JSON for uniqueness)
// NOTE: It is VERY important that fields are added to END of the structure to avoid needed to re-build existing Glue partitions.
//       See https://github.com/awsdocs/amazon-athena-user-guide/blob/master/doc_source/updates-and-partitions.md
type PantherLog struct {
	//  required
	PantherLogType   string            `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`            // nolint(lll)
	PantherRowID     string            `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"` // nolint(lll)
	PantherEventTime timestamp.RFC3339 `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`    // nolint(lll)

	// optional (any)
	PantherAnyIPAddresses    *PantherAnyString `json:"p_any_ip_addresses,omitempty" description:"Panther added field with collection of ip addresses associated with the row"`         // nolint(lll)
	PantherAnyDomainNames    *PantherAnyString `json:"p_any_ip_domain_names,omitempty" description:"Panther added field with collection of domain names associated with the row"`      // nolint(lll)
	PantherAnyAWSAccountIds  *PantherAnyString `json:"p_any_aws_account_ids,omitempty" description:"Panther added field with collection of aws account ids associated with the row"`   // nolint(lll)
	PantherAnyAWSInstanceIds *PantherAnyString `json:"p_any_aws_instance_ids,omitempty" description:"Panther added field with collection of aws instance ids associated with the row"` // nolint(lll)
	PantherAnyAWSARNs        *PantherAnyString `json:"p_any_aws_arns,omitempty" description:"Panther added field with collection of aws arns associated with the row"`                 // nolint(lll)
	PantherAnyAWSTags        *PantherAnyString `json:"p_any_aws_tags,omitempty" description:"Panther added field with collection of aws tags associated with the row"`                 // nolint(lll)
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

func (pl *PantherLog) SetRequired(logType string, eventTime timestamp.RFC3339) {
	pl.PantherLogType = logType
	pl.PantherRowID = rowCounter.NewRowID()
	pl.PantherEventTime = eventTime
}

func (pl *PantherLog) AppendAnyIPAddresses(values ...string) {
	if pl.PantherAnyIPAddresses == nil { // lazy create
		pl.PantherAnyIPAddresses = NewPantherAnyString()
	}
	pl.appendAnyString(pl.PantherAnyIPAddresses, values...)
}

func (pl *PantherLog) AppendAnyDomainNames(values ...string) {
	if pl.PantherAnyDomainNames == nil { // lazy create
		pl.PantherAnyDomainNames = NewPantherAnyString()
	}
	pl.appendAnyString(pl.PantherAnyDomainNames, values...)
}

func (pl *PantherLog) AppendAnyAWSAccountIds(values ...string) {
	if pl.PantherAnyAWSAccountIds == nil { // lazy create
		pl.PantherAnyAWSAccountIds = NewPantherAnyString()
	}
	pl.appendAnyString(pl.PantherAnyAWSAccountIds, values...)
}

func (pl *PantherLog) AppendAnyAWSInstanceIds(values ...string) {
	if pl.PantherAnyAWSInstanceIds == nil { // lazy create
		pl.PantherAnyAWSInstanceIds = NewPantherAnyString()
	}
	pl.appendAnyString(pl.PantherAnyAWSInstanceIds, values...)
}

func (pl *PantherLog) AppendAnyAWSARNs(values ...string) {
	if pl.PantherAnyAWSARNs == nil { // lazy create
		pl.PantherAnyAWSARNs = NewPantherAnyString()
	}
	pl.appendAnyString(pl.PantherAnyAWSARNs, values...)
}

// NOTE: value should be of the form <key>:<value>
func (pl *PantherLog) AppendAnyAWSTags(values ...string) {
	if pl.PantherAnyAWSTags == nil { // lazy create
		pl.PantherAnyAWSTags = NewPantherAnyString()
	}
	pl.appendAnyString(pl.PantherAnyAWSTags, values...)
}

func (pl *PantherLog) appendAnyString(any *PantherAnyString, values ...string) {
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
