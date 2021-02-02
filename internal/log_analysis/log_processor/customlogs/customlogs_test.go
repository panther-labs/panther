package customlogs_test

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
https://github.com/panther-labs/panther-enterprise/pull/1505*
* Panther Enterprise is licensed under the terms of a commercial license available from
* Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
* All use, distribution, and/or modification of this software, whether commercial or non-commercial,
* falls under the Panther Commercial License to the extent it is permitted.
*/

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

func ExampleBuild() {
	logSample := `{
	  "method": "GET",
	  "path": "/-/metrics",
	  "format": "html",
	  "controller": "MetricsController",
	  "action": "index",
	  "status": 200,
	  "params": [],
	  "remote_ip": "1.1.1.1",
	  "user_id": null,
	  "username": null,
	  "ua": null,
	  "queue_duration_s": null,
	  "correlation_id": "c01ce2c1-d9e3-4e69-bfa3-b27e50af0268",
	  "cpu_s": 0.05,
	  "db_duration_s": 0,
	  "view_duration_s": 0.00039,
	  "duration_s": 0.0459,
	  "tag": "test",
	  "time": "2019-11-14T13:12:46.156Z"
	}`

	logSchemaJSON := `{
		"schema": "SampleAPI",
		"version": 0,
		"fields": [
			{ "name": "remote_ip", "type": "string", "indicators": ["ip"] , "description": "remote ip address" },
			{ "name": "path", "type": "string", "description": "request URI path" },
			{ "name": "time", "type": "timestamp", "timeFormat": "rfc3339", "isEventTime": true, "description": "event timestamp" },
			{ "name": "method", "type":"string", "description": "request method" },
			{ "name": "duration_s", "type": "float", "description": "duration of the request in seconds" }
		]
	}`
	logSchema := logschema.Schema{}
	fmt.Println("load schema JSON", jsoniter.UnmarshalFromString(logSchemaJSON, &logSchema))

	config, err := customlogs.Build("Custom.API", &logSchema)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	parser, err := config.NewParser(nil)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Println("generated parser", err)
	results, err := parser.ParseLog(logSample)
	fmt.Println("parse sample log", err)
	result := results[0]
	fmt.Println("result log type", result.PantherLogType)
	jsonAPI := pantherlog.ConfigJSON()
	data, err := jsonAPI.Marshal(result)
	if err != nil {
		panic(err)
	}
	// Panther log type field set in JSON
	fmt.Println("p_log_type", gjson.Get(string(data), "p_log_type").Raw)
	// Panther event_time set in JSON in the appropriate format
	fmt.Println("p_event_time", gjson.Get(string(data), "p_event_time").Raw)
	// Duration is proper number
	fmt.Println("duration_s", gjson.Get(string(data), "duration_s").Raw)
	// Panther fields collected
	fmt.Println("p_any_ip_addresses", gjson.Get(string(data), "p_any_ip_addresses").Raw)
	// Output: load schema JSON <nil>
	// generated parser <nil>
	// parse sample log <nil>
	// result log type Custom.API
	// p_log_type "Custom.API"
	// p_event_time "2019-11-14T13:12:46.156Z"
	// duration_s 0.0459
	// p_any_ip_addresses ["1.1.1.1"]
}

func TestLogSchemaParser(t *testing.T) {
	assert := require.New(t)
	logSchema := logschema.Schema{
		Schema:       "Test",
		Description:  "Test schema",
		ReferenceURL: "https://example.com",
		Fields: []logschema.FieldSchema{
			{
				Name:        "ts",
				Description: "Event timestamp",
				ValueSchema: logschema.ValueSchema{
					Type:        logschema.TypeTimestamp,
					TimeFormat:  "rfc3339",
					IsEventTime: true,
				},
			},
			{
				Name:        "foo",
				Description: "Foo field",
				ValueSchema: logschema.ValueSchema{
					Type: logschema.TypeString,
				},
			},
			{
				Name:        "bar",
				Description: "Bar field",
				ValueSchema: logschema.ValueSchema{
					Type: logschema.TypeObject,
					Fields: []logschema.FieldSchema{
						{
							Name:        "baz",
							Description: "Baz field",
							ValueSchema: logschema.ValueSchema{
								Type:       logschema.TypeString,
								Indicators: []string{"domain"},
							},
						},
					},
				},
			},
		},
	}
	config, err := customlogs.Build("Custom.Test", &logSchema)
	assert.NoError(err)
	parser, err := config.NewParser(nil)
	assert.NoError(err)

	//tm := time.Date(2020, 6, 2, 0, 1, 7, 0, time.UTC)
	log := `{"ts": "2020-06-02T00:01:07.000000Z","foo":"bar","bar":{"baz":"foo"}}`
	results, err := parser.ParseLog(log)
	assert.NoError(err)
	assert.Equal(1, len(results))
	//require.Equal(t, tm, results[0].PantherEventTime)
	assert.Equal(customlogs.LogTypePrefix+".Test", results[0].PantherLogType)

	jsonAPI := pantherlog.ConfigJSON()

	data, err := jsonAPI.Marshal(results[0])
	assert.NoError(err)
	data, err = sjson.SetBytesOptions(data, "p_parse_time", "p_parse_time", &sjson.Options{
		Optimistic: true,
	})
	assert.NoError(err)
	data, err = sjson.SetBytesOptions(data, "p_row_id", "p_row_id", &sjson.Options{
		Optimistic: true,
	})
	assert.NoError(err)
	//actualJSON = sjson.Delete(actualJSON, "p_parse_time")
	assert.JSONEq(`{
		"ts":"2020-06-02T00:01:07Z",
		"foo":"bar",
		"bar": {"baz":"foo"},
		"p_event_time": "2020-06-02T00:01:07Z",
		"p_log_type":"Custom.Test",
		"p_row_id": "p_row_id",
		"p_any_domain_names": ["foo"],
		"p_parse_time": "p_parse_time"
	}`, string(data))
}

func TestBuild(t *testing.T) {
	assert := require.New(t)

	for _, schemaFile := range []string{
		"../logschema/testdata/gitlab_api_schema.yml",
		"../logschema/testdata/sample_api_schema.yml",
		"../logschema/testdata/osquery_status_schema.yml",
	} {
		schemaFile := schemaFile
		t.Run(schemaFile, func(t *testing.T) {
			data, err := ioutil.ReadFile(schemaFile)
			assert.NoError(err)
			logSchema := logschema.Schema{}
			assert.NoError(yaml.Unmarshal(data, &logSchema))
			err = logschema.ValidateSchema(&logSchema)
			assert.NoError(err)
			entry, err := customlogs.Build(logSchema.Schema, &logSchema)
			assert.NoError(err)
			assert.NotNil(entry)
		})
	}
}

const sampleApacheCommonLog = `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326`

func TestApacheCommonLog_FastMatch(t *testing.T) {
	for _, schemaFile := range []string{
		"../logschema/testdata/apache_common_log_fastmatch_schema.yml",
		"../logschema/testdata/apache_common_log_regex_schema.yml",
	} {
		schemaFile := schemaFile
		t.Run(schemaFile, func(t *testing.T) {
			assert := require.New(t)
			data, err := ioutil.ReadFile(schemaFile)
			assert.NoError(err)
			logSchema := logschema.Schema{}
			assert.NoError(yaml.Unmarshal(data, &logSchema))
			err = logschema.ValidateSchema(&logSchema)
			assert.NoError(err)
			entry, err := customlogs.Build(logSchema.Schema, &logSchema)
			assert.NoError(err)
			assert.NotNil(entry)
			var expectJSON = fmt.Sprintf(`{
  "remote_ip": "127.0.0.1",
  "user": "frank",
  "timestamp": "10/Oct/2000:13:55:36 -0700",
  "method": "GET",
  "request_uri": "/apache_pb.gif",
  "protocol": "HTTP/1.0",
  "status": 200,
  "bytes_sent": 2326,
  "p_log_type": "%s",
   "p_any_ip_addresses": ["127.0.0.1"],
  "p_event_time": "2000-10-10T20:55:36Z"
}`, entry.String())
			logtesting.TestRegisteredParser(t, entry, entry.String(), sampleApacheCommonLog, expectJSON)
		})
	}
}

//nolint: lll
func TestVPCFlowLog_CSV(t *testing.T) {
	schemaFile := "../logschema/testdata/vpcflow_schema.yml"
	assert := require.New(t)
	data, err := ioutil.ReadFile(schemaFile)
	assert.NoError(err)
	logSchema := logschema.Schema{}
	assert.NoError(yaml.Unmarshal(data, &logSchema))
	err = logschema.ValidateSchema(&logSchema)
	assert.NoError(err)
	entry, err := customlogs.Build(logSchema.Schema, &logSchema)
	assert.NoError(err)
	assert.NotNil(entry)
	const vpcFlowDefaultHeader = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status" // nolint:lll
	const vpcFlowSampleLog = "2 348372346321 eni-00184058652e5a320 52.119.169.95 172.31.20.31 443 48316 6 19 7119 1573642242 1573642284 ACCEPT OK"
	var expectJSON = fmt.Sprintf(`{
  "version": 2,
  "accountId": "348372346321",
  "interfaceId": "eni-00184058652e5a320",
  "srcAddr": "52.119.169.95",
  "dstAddr": "172.31.20.31",
  "srcPort": 443,
  "dstPort": 48316,
  "protocol": 6,
  "packets": 19,
  "bytes": 7119,
  "start": 1573642242,
  "end": 1573642284,
  "action": "ACCEPT",
  "logStatus": "OK",
  "p_log_type": "%s",
  "p_any_ip_addresses": ["172.31.20.31","52.119.169.95"],
  "p_any_aws_account_ids": ["348372346321"],
  "p_event_time": "%s"
}`, entry.String(),
		time.Unix(1573642242, 0).UTC().Format(time.RFC3339Nano))
	logtesting.TestRegisteredParser(t, entry, entry.String(), vpcFlowDefaultHeader)
	logtesting.TestRegisteredParser(t, entry, entry.String(), vpcFlowSampleLog, expectJSON)
}

func TestNameCollisions(t *testing.T) {
	schema := logschema.Schema{
		Fields: []logschema.FieldSchema{
			{
				Name:        "userAgent",
				Description: "userAgent field",
				ValueSchema: logschema.ValueSchema{
					Type: logschema.TypeString,
				},
			},
			{
				Name:        "UserAgent",
				Description: "UserAgent field",
				ValueSchema: logschema.ValueSchema{
					Type: logschema.TypeString,
				},
			},
		},
	}
	entry, err := customlogs.Build("TestNameCollisions", &schema)
	assert := require.New(t)
	assert.Error(err)
	assert.Nil(entry)
}
