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
	jsoniter "github.com/json-iterator/go"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Read YAML file without invoking cfn-flip (which assumes working directory is repo root)
func parseTestYaml(t *testing.T, path string) map[string]interface{} {
	contents, err := ioutil.ReadFile(path)
	require.NoError(t, err)

	var yamlResult map[string]interface{}
	require.NoError(t, yaml.Unmarshal(contents, &yamlResult))

	// Now we have to marshal/unmarshal with json to get rid of map[interface{}]interface{}
	jsonBody, err := jsoniter.Marshal(&yamlResult)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, jsoniter.Unmarshal(jsonBody, &result))
	return result
}

func TestEmbedAPIsNoChange(t *testing.T) {
	cfn := parseTestYaml(t, "testdata/no-api.yml")
	expectedMap := parseTestYaml(t, "testdata/no-api.yml")

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
	cfn := parseTestYaml(t, "testdata/valid-api.yml")
	expectedMap := parseTestYaml(t, "testdata/valid-api-expected-output.yml")

	require.NoError(t, embedAPIs(cfn))

	// The mixing of map[interface{}]interface{} and map[string]interface{} makes direct comparisons hard,
	// marshal first as yaml and then compare
	result, err := yaml.Marshal(cfn)
	require.NoError(t, err)
	expected, err := yaml.Marshal(expectedMap)
	require.NoError(t, err)

	assert.YAMLEq(t, string(expected), string(result))
}
