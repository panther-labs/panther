package testutil

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

// used for test code that should NOT be in production code

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// used by log parsers to validate records
func EqualPantherLog(t *testing.T, expectedEvent *parsers.PantherLog, events []*parsers.PantherLog) {
	require.Equal(t, 1, len(events))
	event := events[0]
	require.NotNil(t, event)
	require.NotNil(t, event.Event())

	event.SetEvent(expectedEvent.Event()) // set pack ptr to so equal test works

	// rowid changes each time
	require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
	expectedEvent.PantherRowID = event.PantherRowID

	// PantherParseTime is set to time.Now().UTC(). Require not nil
	require.NotNil(t, event.PantherParseTime)
	expectedEvent.PantherParseTime = event.PantherParseTime

	// For nil event times, expect Panther to set the event time to the parse time.
	if expectedEvent.PantherEventTime == nil {
		expectedEvent.PantherEventTime = event.PantherParseTime
	}

	require.Equal(t, expectedEvent.Event(), event.Event())
}
