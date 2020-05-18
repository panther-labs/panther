package null_test

import (
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/null"
	"github.com/stretchr/testify/require"
)

func TestNullStringCodec(t *testing.T) {
	type A struct {
		Foo null.String `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"bar"}`, &a)
		require.NoError(t, err)
		require.Equal(t, "bar", a.Foo.Value)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"bar"}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":""}`, &a)
		require.NoError(t, err)
		require.Equal(t, "", a.Foo.Value)
		require.True(t, a.Foo.OK)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":null}`, &a)
		require.NoError(t, err)
		require.Equal(t, "", a.Foo.Value)
		require.False(t, a.Foo.OK)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
}

func BenchmarkNullString(b *testing.B) {
	data := []byte(`{"foo":"bar","bar":"baz","baz":null}`)
	data12 := []byte(`{"f01":"01","f02":"02","f03":"03","f04":"04","f05":"05","f06":"06","f07":"07","f08":"08","f09":"09","f10":"10","f11":"11","f12":null}`)
	type A struct {
		Foo null.String `json:"foo,omitempty"`
		Bar null.String `json:"bar,omitempty"`
		Baz null.String `json:"baz,omitempty"`
	}
	type B struct {
		Foo *string `json:"foo,omitempty"`
		Bar *string `json:"bar,omitempty"`
		Baz *string `json:"baz,omitempty"`
	}
	type DozenFieldsA struct {
		F01 null.String `json:"f01,omitempty"`
		F02 null.String `json:"f02,omitempty"`
		F03 null.String `json:"f03,omitempty"`
		F04 null.String `json:"f04,omitempty"`
		F05 null.String `json:"f05,omitempty"`
		F06 null.String `json:"f06,omitempty"`
		F07 null.String `json:"f07,omitempty"`
		F08 null.String `json:"f08,omitempty"`
		F09 null.String `json:"f09,omitempty"`
		F10 null.String `json:"f10,omitempty"`
		F11 null.String `json:"f11,omitempty"`
		F12 null.String `json:"f12,omitempty"`
	}
	type DozenFieldsB struct {
		F01 *string `json:"f01,omitempty"`
		F02 *string `json:"f02,omitempty"`
		F03 *string `json:"f03,omitempty"`
		F04 *string `json:"f04,omitempty"`
		F05 *string `json:"f05,omitempty"`
		F06 *string `json:"f06,omitempty"`
		F07 *string `json:"f07,omitempty"`
		F08 *string `json:"f08,omitempty"`
		F09 *string `json:"f09,omitempty"`
		F10 *string `json:"f10,omitempty"`
		F11 *string `json:"f11,omitempty"`
		F12 *string `json:"f12,omitempty"`
	}

	b.ReportAllocs()
	b.Run("NullString Unmarshal 3 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := A{}
			iter.ResetBytes(data)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
	b.Run("*string Unmarshal 3 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := B{}
			iter.ResetBytes(data)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
	b.Run("NullString Marshal 3 fields", func(b *testing.B) {
		a := A{
			Foo: null.String{
				Value: "foo",
				OK:    true,
			},
			Bar: null.String{
				Value: "bar",
				OK:    true,
			},
		}
		for i := 0; i < b.N; i++ {
			_, _ = jsoniter.Marshal(&a)
		}
	})
	b.Run("*string Marshal 3 fields", func(b *testing.B) {
		foo := "foo"
		bar := "bar"
		v := B{
			Foo: &foo,
			Bar: &bar,
		}
		for i := 0; i < b.N; i++ {
			_, _ = jsoniter.Marshal(&v)
		}
	})
	b.Run("NullString Unmarshal 12 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := DozenFieldsA{}
			iter.ResetBytes(data12)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
	b.Run("*string Unmarshal 12 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := DozenFieldsB{}
			iter.ResetBytes(data12)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
}
