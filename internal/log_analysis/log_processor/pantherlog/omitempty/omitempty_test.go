package omitempty

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

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(New("json"))

	type A struct {
		Foo    string `json:"foo"`
		Bar    string `json:",omitempty"`
		Baz    string
		Nested *A `json:"nested"`
	}
	type B struct {
		Qux string `json:"qux"`
		A
		Ignore string `json:"-"`
	}
	{
		out, err := api.MarshalToString(&A{
			Nested: &A{},
		})
		require.NoError(t, err)
		require.Equal(t, `{"nested":{}}`, out)
	}
	{
		out, err := api.MarshalToString(&A{})
		require.NoError(t, err)
		require.Equal(t, `{}`, out)
	}
	{
		out, err := api.MarshalToString(&B{})
		require.NoError(t, err)
		require.Equal(t, `{}`, out)
	}
	{
		out, err := api.MarshalToString(&B{
			Qux: "qux",
			A: A{
				Foo: "foo",
			},
		})
		require.NoError(t, err)
		require.Equal(t, `{"qux":"qux","foo":"foo"}`, out)
	}
}
