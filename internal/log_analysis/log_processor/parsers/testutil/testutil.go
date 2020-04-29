package testutil

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

// used for test code that should NOT be in production code

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/stretchr/testify/require"
)

// CheckPantherEvent verifies PantherEvent returned by logs.
// Order of fields is irrelevant.
func CheckPantherEvent(t *testing.T, src parsers.PantherEventer, logType string, tm time.Time, fields ...parsers.PantherField) {
	t.Helper()
	// Check PantherEventer works for zero value
	require.NotPanics(t, func() {
		typ := reflect.Indirect(reflect.ValueOf(src)).Type()
		blank := reflect.New(typ)
		// Assert it works for blank value
		_ = blank.Interface().(parsers.PantherEventer).PantherEvent()
	})
	actual := src.PantherEvent()
	expect := parsers.NewEvent(logType, tm, fields...)
	// Sort fields so events can be checked for equality
	sort.Sort(actual)
	sort.Sort(expect)
	require.Equal(t, expect, actual)
}

// CheckPantherParserJSON checks events produced by a parsers.LogParser on log input
// It can test parsers that return zero, one or many events
func CheckPantherParserJSON(t *testing.T, log string, parser parsers.Parser, expect ...parsers.PantherEventer) {
	t.Helper()
	results, err := parser.Parse(log)
	require.NoError(t, err)
	require.NotNil(t, results)
	// Prepend the required log arg to more
	require.Equal(t, len(expect), len(results), "Invalid number of pather logs produced by parser")
	for i, result := range results {
		expect, err := parsers.RepackJSON(expect[i])
		require.NoError(t, err)
		PantherLogJSONEq(t, expect, result)
	}
}

// CheckPantherParserJSON checks events produced by a parsers.LogParser on log input
// It can test parsers that return zero, one or many events
func CheckParser(t *testing.T, log, logType string, expect ...parsers.PantherEventer) {
	t.Helper()
	parser, err := parsers.NewParser(logType)
	require.NoError(t, err)
	require.NotNil(t, parser)
	results, err := parser.Parse(log)
	require.NoError(t, err)
	require.NotNil(t, results)
	// Prepend the required log arg to more
	require.Equal(t, len(expect), len(results), "Invalid number of pather logs produced by parser")
	for i, result := range results {
		expect, err := parsers.RepackJSON(expect[i])
		require.NoError(t, err)
		PantherLogJSONEq(t, expect, result)
	}
}

// PantherLogJSONEq asserts that two JSON panther logs are equivalent.
//
func PantherLogJSONEq(t *testing.T, expected, actual *parsers.PantherLogJSON, msgAndArgs ...interface{}) bool {
	t.Helper()
	require.Equal(t, expected.EventTime, actual.EventTime)
	require.Equal(t, expected.LogType, actual.LogType)
	var expectedJSONAsInterface, actualJSONAsInterface map[string]interface{}

	if err := json.Unmarshal(expected.JSON, &expectedJSONAsInterface); err != nil {
		t.Errorf(fmt.Sprintf("Expected value ('%s') is not valid json.\nJSON parsing error: '%s'", expected, err.Error()), msgAndArgs...)
		return false
	}

	if err := json.Unmarshal(actual.JSON, &actualJSONAsInterface); err != nil {
		t.Errorf(fmt.Sprintf("Expected value ('%s') is not valid json.\nJSON parsing error: '%s'", actual, err.Error()), msgAndArgs...)
		return false
	}
	require.NotEmpty(t, expectedJSONAsInterface["p_row_id"])
	require.NotEmpty(t, expectedJSONAsInterface["p_parse_time"])
	delete(expectedJSONAsInterface, "p_row_id")
	delete(actualJSONAsInterface, "p_row_id")
	delete(expectedJSONAsInterface, "p_parse_time")
	delete(actualJSONAsInterface, "p_parse_time")
	if expected.EventTime.IsZero() {
		// Delete EventTime to test the rest of the fields
		delete(expectedJSONAsInterface, "p_event_time")
		delete(actualJSONAsInterface, "p_event_time")
	}
	require.Equal(t, expectedJSONAsInterface, actualJSONAsInterface, msgAndArgs...)
	return true
}
