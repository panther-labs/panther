package mage

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/tools/cfnparse"
)

func TestEmbedAPIsNoChange(t *testing.T) {
	cfn, err := cfnparse.ParseTemplate("testdata/no-api.yml")
	require.NoError(t, err)
	expectedMap, err := cfnparse.ParseTemplate("testdata/no-api.yml")
	require.NoError(t, err)

	require.NoError(t, embedAPIs(cfn))

	// The mixing of map[interface{}]interface{} and map[string]interface{} makes direct comparisons hard,
	// marshal first as yaml and then compare
	result, err := yaml.Marshal(cfn)
	require.NoError(t, err)
	expected, err := yaml.Marshal(expectedMap)
	require.NoError(t, err)

	assert.YAMLEq(t, string(expected), string(result))
}

func TestEmbedAPIs(t *testing.T) {
	cfn, err := cfnparse.ParseTemplate("testdata/valid-api.yml")
	require.NoError(t, err)
	expectedMap, err := cfnparse.ParseTemplate("testdata/valid-api-expected-output.yml")
	require.NoError(t, err)

	require.NoError(t, embedAPIs(cfn))

	// The mixing of map[interface{}]interface{} and map[string]interface{} makes direct comparisons hard,
	// marshal first as yaml and then compare
	result, err := yaml.Marshal(cfn)
	require.NoError(t, err)
	expected, err := yaml.Marshal(expectedMap)
	require.NoError(t, err)

	assert.YAMLEq(t, string(expected), string(result))
}
