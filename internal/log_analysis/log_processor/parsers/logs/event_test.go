package logs

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
	require.Empty(t, event.AppendFieldsTo(nil))
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
	require.Empty(t, event.AppendFieldsTo(nil))
}
