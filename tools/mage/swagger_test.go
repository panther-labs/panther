package mage

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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSwaggerPattern(t *testing.T) {
	assert.False(t, swaggerPattern.MatchString(""))
	assert.False(t, swaggerPattern.MatchString("\n      DefinitionBody: myfile.json"))
	assert.False(t, swaggerPattern.MatchString("\n      DefinitionBody: \napi.yml"))
	assert.False(t, swaggerPattern.MatchString("DefinitionBody: api.yml"))

	assert.True(t, swaggerPattern.MatchString("\n      DefinitionBody:api.yml"))
	assert.True(t, swaggerPattern.MatchString("\n      DefinitionBody: api/compliance.yml  "))
	assert.True(t, swaggerPattern.MatchString("\n      DefinitionBody:    api/compliance.yml # trailing comment"))

	// Ensure spaces and comments are consumed
	replaced := swaggerPattern.ReplaceAllString("\n      DefinitionBody: api/compliance.yml # trailing comment", "X")
	assert.Equal(t, replaced, "X")
}

func TestEmbedAPIsNoChange(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/no-api.yml")
	require.NoError(t, err)

	transformed, err := embedAPIs(data)
	require.NoError(t, err)
	assert.Nil(t, transformed) // no changes - nil is returned
}

func TestEmbedAPIs(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/valid-api.yml")
	require.NoError(t, err)

	transformed, err := embedAPIs(data)
	require.NoError(t, err)

	expected, err := ioutil.ReadFile("testdata/valid-api-expected-output.yml")
	require.NoError(t, err)
	assert.Equal(t, string(expected), string(transformed))
}
