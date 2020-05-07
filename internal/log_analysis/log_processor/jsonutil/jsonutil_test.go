package jsonutil

import (
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestAthenaRewrite(t *testing.T) {
	field := "@name"
	mapped := RewriteFieldNameAthena(field)
	require.Equal(t, "_at_sign_name", mapped)
}

func TestJSONIterExtension(t *testing.T) {
	RegisterAthenaRewrite()

	type S struct {
		Type string `json:"@type"`
	}
	var value S
	err := jsoniter.UnmarshalFromString(`{"@type":"foo"}`, &value)
	require.NoError(t, err)
	data, err := jsoniter.MarshalToString(&value)
	require.NoError(t, err)
	require.Equal(t, `{"_at_sign_type":"foo"}`, data)
}
