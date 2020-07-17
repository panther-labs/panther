package null

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-playground/validator.v9"
)

func TestRegisterValidators(t *testing.T) {
	v := validator.New()
	type T struct {
		RequiredString String `validate:"required,eq=foo"`
		RequiredInt64  Int64  `validate:"required,eq=42"`
	}
	assert.NoError(t, v.Struct(T{}))
	RegisterValidators(v)
	require.Error(t, v.Struct(T{}))
	require.Error(t, v.Struct(T{
		RequiredString: FromString("bar"),
		RequiredInt64:  FromInt64(42),
	}))
	require.Error(t, v.Struct(T{
		RequiredString: FromString("foo"),
		RequiredInt64:  FromInt64(0),
	}))
	require.NoError(t, v.Struct(T{
		RequiredString: FromString("foo"),
		RequiredInt64:  FromInt64(42),
	}))
}
