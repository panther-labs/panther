package tcodec

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestNewOptions(t *testing.T) {
	{
		var ext Extension
		require.Equal(t, DefaultTagName, ext.TagName())
	}
	{
		ext := NewExtension(Config{})
		require.Equal(t, DefaultTagName, ext.TagName())
	}
	{
		ext := NewExtension(Config{
			OverrideEncoder: LayoutCodec(time.RFC3339Nano),
		})
		require.NotNil(t, ext.timeEncoderFunc(nil))
		require.Nil(t, ext.timeDecoderFunc(nil))
	}
	{
		ext := NewExtension(Config{
			OverrideDecoder: LayoutCodec(time.RFC3339Nano),
		})
		require.NotNil(t, ext.timeDecoderFunc(nil))
		require.Nil(t, ext.timeEncoderFunc(nil))
		require.Equal(t, DefaultTagName, ext.TagName())
	}
	{
		ext := NewExtension(Config{
			TagName: "foo",
		})
		require.Equal(t, "foo", ext.TagName())
		type T struct {
			Time time.Time `json:"tm" foo:"rfc3339"`
		}
		v := T{}
		api := jsoniter.Config{}.Froze()
		api.RegisterExtension(ext)
		require.NoError(t, api.UnmarshalFromString(`{"tm":"2006-01-02T15:04:05.999Z"}`, &v))
		expect := time.Date(2006, 1, 2, 15, 4, 5, 999*int(time.Millisecond), time.UTC)
		require.Equal(t, expect.Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano))
	}
	{
		loc, err := time.LoadLocation("Europe/Athens")
		require.NoError(t, err)
		ext := NewExtension(Config{
			Location: loc,
		})
		type T struct {
			Time time.Time `json:"tm" tcodec:"rfc3339"`
			Foo  string
		}
		v := T{}
		api := jsoniter.Config{}.Froze()
		api.RegisterExtension(ext)
		require.NoError(t, api.UnmarshalFromString(`{"tm":"2006-01-02T15:04:05.999Z"}`, &v))
		require.Equal(t, loc, v.Time.Location())
	}
	{
		ext := NewExtension(Config{
			DefaultCodec: UnixSecondsCodec(),
		})
		type T struct {
			Time time.Time `json:"tm"`
			Foo  string
		}
		v := T{}
		api := jsoniter.Config{}.Froze()
		api.RegisterExtension(ext)
		require.NoError(t, api.UnmarshalFromString(`{"tm":"1595257966.369"}`, &v))
		expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
		require.Equal(t, expect.Local().Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano))
	}
}
