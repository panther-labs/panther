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
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestAnyStringMarshal(t *testing.T) {
	var any PantherAnyString

	// nil case
	expectedJSON := `[]`
	actualJSON, err := jsoniter.Marshal(&any)
	require.NoError(t, err)
	require.Equal(t, expectedJSON, string(actualJSON))

	// non-nil case
	any.set = map[string]struct{}{
		"a": {},
		"b": {},
		"c": {},
	}
	expectedJSON = `["a","b","c"]` // should be sorted
	actualJSON, err = jsoniter.Marshal(&any)
	require.NoError(t, err)
	require.Equal(t, expectedJSON, string(actualJSON))
}

func TestAnyStringUnmarshal(t *testing.T) {
	var any PantherAnyString

	// nil case
	jsonString := `[]`
	expectedAny := PantherAnyString{
		set: make(map[string]struct{}),
	}
	err := jsoniter.Unmarshal(([]byte)(jsonString), &any)
	require.NoError(t, err)
	require.Equal(t, expectedAny, any)

	// non-nil case
	jsonString = `["a"]`
	expectedAny = PantherAnyString{
		set: map[string]struct{}{
			"a": {},
		},
	}
	err = jsoniter.Unmarshal(([]byte)(jsonString), &any)
	require.NoError(t, err)
	require.Equal(t, expectedAny, any)
}

func TestAppendAnyString(t *testing.T) {
	value := "a"
	expectedAny := &PantherAnyString{
		set: map[string]struct{}{
			value: {},
		},
	}
	any := NewPantherAnyString()
	AppendAnyString(any, value)
	require.Equal(t, expectedAny, any)
}

func TestAppendAnyStringWithEmptyString(t *testing.T) {
	value := ""                                                  // should not be stored
	expectedAny := &PantherAnyString{set: map[string]struct{}{}} // empty map
	any := NewPantherAnyString()
	AppendAnyString(any, value)
	require.Equal(t, expectedAny, any)
}

func TestSetRequired(t *testing.T) {
	event := PantherLog{}
	logType := "Data.Source"
	eventTime := (timestamp.RFC3339)(time.Date(2020, 1, 2, 3, 0, 0, 0, time.UTC))
	expectedEvent := PantherLog{
		PantherLogType:   &logType,
		PantherEventTime: &eventTime,
	}
	event.SetCoreFields(logType, eventTime)
	expectedEvent.PantherRowID = event.PantherRowID // set because it is random
	require.Equal(t, expectedEvent, event)
}

func TestAppendAnyIPAddresses(t *testing.T) {
	event := PantherLog{}
	value := "a"
	expectedAny := &PantherAnyString{
		set: map[string]struct{}{
			value: {},
		},
	}
	event.AppendAnyIPAddresses(value)
	require.Equal(t, expectedAny, event.PantherAnyIPAddresses)

	event = PantherLog{}
	event.AppendAnyIPAddressPtrs(&value)
	require.Equal(t, expectedAny, event.PantherAnyIPAddresses)
}

func TestAppendAnyDomainNames(t *testing.T) {
	event := PantherLog{}
	value := "a"
	expectedAny := &PantherAnyString{
		set: map[string]struct{}{
			value: {},
		},
	}
	event.AppendAnyDomainNames(value)
	require.Equal(t, expectedAny, event.PantherAnyDomainNames)

	event = PantherLog{}
	event.AppendAnyDomainNamePtrs(&value)
	require.Equal(t, expectedAny, event.PantherAnyDomainNames)
}
