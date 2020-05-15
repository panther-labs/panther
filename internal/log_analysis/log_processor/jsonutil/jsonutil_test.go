package jsonutil

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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestEncoderNamingStrategy(t *testing.T) {
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(NewEncoderNamingStrategy(func(name string) string {
		if name == "foo" {
			return "bar"
		}
		return name
	}))

	type S struct {
		Foo string `json:"foo"`
		Baz string `json:"baz"`
	}
	value := S{}
	err := api.UnmarshalFromString(`{"foo":"foo","baz":"baz"}`, &value)
	require.NoError(t, err)
	require.Equal(t, S{Foo: "foo", Baz: "baz"}, value)
	data, err := api.MarshalToString(&value)
	require.NoError(t, err)
	require.Equal(t, `{"bar":"foo","baz":"baz"}`, data)
}
