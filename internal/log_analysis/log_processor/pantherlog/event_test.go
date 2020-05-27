package pantherlog

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvent(t *testing.T) {
	// Time has non-UTC timezone to check NewEvent converts timestamp to UTC
	tm, err := time.Parse(time.RFC3339Nano, "2020-05-15T13:04:01.095878483+03:00")
	assert.NoError(t, err)
	event := NewEvent("foo", tm)
	require.NotNil(t, event)
	require.Equal(t, tm.UTC(), event.Timestamp)
	require.Equal(t, "foo", event.LogType)
	event.Reset()
	require.Equal(t, "", event.LogType)
	require.Equal(t, time.Time{}, event.Timestamp)
	require.Empty(t, event.AppendValuesTo(nil))
}

func TestEvent_Values(t *testing.T) {
	tm, err := time.Parse(time.RFC3339Nano, "2020-05-15T13:04:01.095878483+03:00")
	assert.NoError(t, err)
	event := NewEvent("foo", tm, IPAddress("invalid ip address"), IPAddress("8.8.8.8"), IPAddress("1.1.1.1"))
	require.NotNil(t, event)
	require.Equal(t, tm.UTC(), event.Timestamp)
	require.Equal(t, "foo", event.LogType)
	// Check values are ordered and invalid ip address was skipped
	require.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, event.Values(KindIPAddress))
	event.Reset()
	require.Equal(t, "", event.LogType)
	require.Equal(t, time.Time{}, event.Timestamp)
	require.Nil(t, event.Values(KindIPAddress))
	require.Empty(t, event.AppendValuesTo(nil))
}
