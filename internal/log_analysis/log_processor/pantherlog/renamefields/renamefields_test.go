package renamefields

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

func TestEncoderNamingStrategy(t *testing.T) {
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(New(func(name string) string {
		if name == "foo" {
			return "bar"
		}
		return name
	}))

	type T struct {
		Foo string `json:"foo"`
		Baz string `json:"baz"`
	}
	value := T{}
	assert := require.New(t)
	err := api.UnmarshalFromString(`{"foo":"foo","baz":"baz"}`, &value)
	assert.NoError(err)
	assert.Equal(T{Foo: "foo", Baz: "baz"}, value)
	data, err := api.MarshalToString(&value)
	assert.NoError(err)
	assert.Equal(`{"bar":"foo","baz":"baz"}`, data)
}
