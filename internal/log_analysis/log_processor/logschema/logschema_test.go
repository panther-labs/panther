package logschema

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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
)

func TestValueSpecValidate(t *testing.T) {
	assert := require.New(t)

	err := ValidateSchema(&Schema{})
	// We don't check more so that if the schema.json gets updated we don't have to update the test
	assert.Error(err)
	assert.NotEmpty(ValidationErrors(err))
	for _, schemaFile := range []string{
		"./testdata/gitlab_api_schema.yml",
		"./testdata/sample_api_schema.yml",
		"./testdata/osquery_status_schema.yml",
		"./testdata/apache_common_log_fastmatch_schema.yml",
		"./testdata/apache_common_log_regex_schema.yml",
		"./testdata/vpcflow_schema.yml",
	} {
		schemaFile := schemaFile
		t.Run(schemaFile, func(t *testing.T) {
			data, err := ioutil.ReadFile(schemaFile)
			assert.NoError(err)
			logSchema := Schema{}
			assert.NoError(yaml.Unmarshal(data, &logSchema))
			err = ValidateSchema(&logSchema)
			problems := ValidationErrors(err)
			assert.Empty(problems)
			assert.NoError(err)
		})
	}
}

func TestJSONUnmarshal(t *testing.T) {
	type testCase struct {
		Name   string
		Input  string
		Expect *ValueSchema
	}
	for _, tc := range []testCase{
		{
			`string`,
			`type: string`,
			&ValueSchema{
				Type: TypeString,
			},
		},
		{
			`timestamp unix milliseconds`,
			`
type: timestamp
timeFormat: unix_ms
`,
			&ValueSchema{
				Type:       TypeTimestamp,
				TimeFormat: "unix_ms",
			},
		},
		{
			`float`,
			`type: float`,
			&ValueSchema{
				Type: TypeFloat,
			},
		},
		{
			`object`,
			`
type: object
fields:
- name: user
  type: string
- name: keywords
  type: array
  element:
    type: string
`,
			&ValueSchema{
				Type: TypeObject,
				Fields: []FieldSchema{
					{
						Name:        "user",
						ValueSchema: ValueSchema{Type: TypeString},
					},
					{
						Name:        "keywords",
						ValueSchema: ValueSchema{Type: TypeArray, Element: &ValueSchema{Type: TypeString}},
					},
				},
			},
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			assert := require.New(t)
			actual := ValueSchema{}
			err := yaml.Unmarshal([]byte(tc.Input), &actual)
			if tc.Expect != nil {
				assert.NoError(err)
				assert.Equal(tc.Expect, &actual)
			} else {
				assert.Error(err)
			}
		})
	}
}

func TestLogSpec_UnmarshalYAML(t *testing.T) {
	input := testutil.MustReadFileString(`./testdata/sample_api_schema.yml`)
	actual := Schema{}
	err := yaml.Unmarshal([]byte(input), &actual)
	require.NoError(t, err, "Failed to parse log spec YAML")
	expect := Schema{
		Schema: "SampleAPI",
		Fields: []FieldSchema{
			{
				Name:        `time`,
				Description: `Event timestamp`,
				Required:    true,
				ValueSchema: ValueSchema{
					Type:        TypeTimestamp,
					TimeFormat:  `rfc3339`,
					IsEventTime: true,
				},
			},
			{
				Name:        `method`,
				Description: `The HTTP method used for the request`,
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name:        `path`,
				Description: `The path used for the request`,
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name:        `remote_ip`,
				Description: `The remote IP address the request was made from`,
				ValueSchema: ValueSchema{
					Type:       TypeString,
					Indicators: []string{"ip"},
				},
			},
			{
				Name:        `duration_s`,
				Description: `The number of seconds the request "took" to complete`,
				ValueSchema: ValueSchema{
					Type: TypeFloat,
				},
			},
			{
				Name:        `format`,
				Description: `Response format`,
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name:        `user_id`,
				Description: `The id of the user that made the request`,
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name:        `params`,
				Description: `Request URI query parameters`,
				ValueSchema: ValueSchema{
					Type: TypeArray,
					Element: &ValueSchema{
						Type: TypeObject,
						Fields: []FieldSchema{
							{
								Name:        `key`,
								Description: `Query parameter name`,
								ValueSchema: ValueSchema{
									Type: TypeString,
								},
							},
							{
								Name:        `value`,
								Description: `Query parameter value`,
								ValueSchema: ValueSchema{
									Type: TypeString,
								},
							},
						},
					},
				},
			},
			{
				Name:        `tag`,
				Description: `Tag for the request`,
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name:        `ua`,
				Description: `UserAgent header`,
				ValueSchema: ValueSchema{Type: TypeString},
			},
		},
	}
	require.Equal(t, expect, actual)
}
