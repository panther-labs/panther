package tcodec

import (
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestUnixMilliseconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259*time.Millisecond.Nanoseconds()), time.UTC)
	actual := UnixMilliseconds(1590364207259)
	require.Equal(t, expect, actual.UTC())
}
func TestUnixSeconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259*time.Millisecond.Nanoseconds()), time.UTC)
	actual := UnixSeconds(1590364207.259)
	require.Equal(t, expect, actual.UTC())
}

func TestRegisterDecoder(t *testing.T) {
	require.NoError(t, RegisterDecoder("foo", TimeLayout("2006")))
	require.Error(t, RegisterDecoder("bar", nil))
	require.Error(t, RegisterDecoder("foo", TimeLayout("2006")))
	require.Panics(t, func() {
		MustRegisterDecoder("foo", nil)
	})
	require.Nil(t, LookupDecoder("baz"))
	require.NotNil(t, LookupDecoder("foo"))

	type T struct {
		Time time.Time `json:"time" tcodec:"foo"`
		Unix time.Time `json:"unix" tcodec:"unix"`
	}
	v := T{}
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(NewDecoderExtension())
	require.NoError(t, api.UnmarshalFromString(`{"time":"2020"}`, &v))
	expect := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	require.Equal(t, expect, v.Time.UTC())
	v = T{}
	require.Error(t, api.UnmarshalFromString(`{"time":"abc"}`, &v))
	v = T{}
	require.Error(t, api.UnmarshalFromString(`{"time":123abc}`, &v))
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{"time":null}`, &v))
	require.Equal(t, time.Time{}, v.Time)
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{}`, &v))
	require.Equal(t, time.Time{}, v.Time)
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{"unix":null}`, &v))
	require.Equal(t, time.Time{}, v.Time)
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{"unix":""}`, &v))
	require.Equal(t, time.Time{}, v.Unix)

	v = T{}
	expect = time.Date(2020, 2, 4, 13, 20, 24, 123456789*int(time.Microsecond), time.UTC)
	unix := expect.UnixNano()
	unixSeconds := time.Duration(unix).Seconds()
	input := fmt.Sprintf(`{"unix":%f}`, unixSeconds)
	require.NoError(t, api.UnmarshalFromString(input, &v))
	require.Equal(t, expect.Format(time.RFC3339Nano), v.Unix.UTC().Format(time.RFC3339Nano))

	v = T{}
	input = fmt.Sprintf(`{"unix":"%f"}`, unixSeconds)
	require.NoError(t, api.UnmarshalFromString(input, &v))
	require.Equal(t, expect.Format(time.RFC3339Nano), v.Unix.UTC().Format(time.RFC3339Nano))

	require.Error(t, api.UnmarshalFromString(`{"unix":{}}`, &v))
	require.Error(t, api.UnmarshalFromString(`{"unix":[]}`, &v))
	require.Error(t, api.UnmarshalFromString(`{"unix":true}`, &v))
}
