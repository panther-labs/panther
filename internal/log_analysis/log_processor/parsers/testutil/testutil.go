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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// // used by log parsers to validate records
// func EqualPantherLog(t *testing.T, expectedEvent *parsers.PantherLog, events []*parsers.PantherLogJSON, parseErr error) {
// 	require.NoError(t, parseErr)
// 	require.Equal(t, 1, len(events))
// 	event := events[0]
// 	require.NotNil(t, event)

// 	s := string(event.JSON)
// 	_ = s
// 	p := parsers.PantherLog{}
// 	err := jsoniter.Unmarshal(event.JSON, &p)
// 	require.NoError(t, err)

// 	// rowid changes each time
// 	require.Greater(t, len(*p.PantherRowID), 0) // ensure something is there.

// 	// PantherParseTime is set to time.Now().UTC(). Require not nil
// 	require.NotNil(t, p.PantherParseTime)
// 	// serialize as JSON using back pointers to compare
// 	eventJSON, err := jsoniter.MarshalToString(p.Event())
// 	require.NoError(t, err)
// 	expectedJSON, err := jsoniter.MarshalToString(expectedEvent.Event())
// 	require.NoError(t, err)

// 	require.JSONEq(t, expectedJSON, eventJSON)
// }

// func CheckPantherParser(t *testing.T, log string, parser parsers.LogParser, expect *parsers.PantherLog, expectMore ...*parsers.PantherLog) {
// 	t.Helper()
// 	p := parser.New()
// 	results, err := p.Parse(log)
// 	require.NoError(t, err)
// 	require.NotNil(t, results)
// 	// Prepend the required log arg to more
// 	expectMore = append([]*parsers.PantherLog{expect}, expectMore...)
// 	require.Equal(t, len(expectMore), len(results), "Invalid number of pather logs produced by parser")
// 	for i, result := range results {
// 		expect := expectMore[i].Log()
// 		require.Equal(t, p.LogType(), result.LogType)
// 		require.Equal(t, expect.EventTime, result.EventTime)
// 		require.JSONEq(t, string(expect.JSON), string(result.JSON), nil)
// 	}
// }

func CheckPantherEvent(t *testing.T, event parsers.PantherEventer, typ string, tm time.Time, fields ...parsers.PantherField) {
	t.Helper()
	actualTyp, actualTm, actualFields := event.PantherEvent()
	require.Equal(t, typ, actualTyp)
	require.Equal(t, tm, actualTm)
	require.Equal(t, fields, actualFields)
}
func CheckPantherParserJSON(t *testing.T, log string, parser parsers.LogParser, expect ...parsers.PantherEventer) {
	t.Helper()
	p := parser.New()
	results, err := p.Parse(log)
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
	require.Equal(t, expectedJSONAsInterface, actualJSONAsInterface, msgAndArgs...)
	return true
}
