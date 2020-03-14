package numerics

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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInteger(t *testing.T) {
	var i Integer = 123
	assert.Equal(t, "123", i.String())

	jsonString, err := i.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, "123", (string)(jsonString))

	// no quotes
	err = i.UnmarshalJSON(([]byte)(`321`))
	require.NoError(t, err)
	assert.Equal(t, (Integer)(321), i)

	// quotes
	err = i.UnmarshalJSON(([]byte)(`"321""`))
	require.NoError(t, err)
	assert.Equal(t, (Integer)(321), i)

	// not an int
	err = i.UnmarshalJSON(([]byte)(`foo`))
	require.Error(t, err)

	var nilInt *Integer
	assert.Equal(t, "nil", nilInt.String())

	jsonString, err = nilInt.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, "nil", (string)(jsonString))

	err = nilInt.UnmarshalJSON(([]byte)("321"))
	require.NoError(t, err)
	assert.Equal(t, (*Integer)(nil), nilInt)
}
