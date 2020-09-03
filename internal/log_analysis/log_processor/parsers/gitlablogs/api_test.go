package gitlablogs

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestGitLabAPI(t *testing.T) {
	// nolint:lll
	log := `{
  "time":"2018-10-29T12:49:42.123Z",
  "severity":"INFO",
  "duration_s":709.08,
  "db_duration_s":14.59,
  "view_duration_s":694.49,
  "status":200,
  "method":"GET",
  "path":"/api/v4/projects",
  "params":[{"key":"action","value":"git-upload-pack"},{"key":"changes","value":"_any"},{"key":"key_id","value":"secret"},{"key":"secret_token","value":"[FILTERED]"}],
  "host":"localhost",
  "remote_ip":"::1",
  "ua":"Ruby",
  "route":"/api/:version/projects",
  "user_id":1,
  "username":"root",
  "queue_duration_s":100.31,
  "gitaly_calls":30,
  "gitaly_duration_s":5.36,
  "redis_calls": 10,
  "redis_duration_s": 5.1,
  "correlation_id": "895c51dc-96c8-4f18-8be4-65252b17a324",
  "meta.user":"testuser",
  "meta.project":"testuser/jumbotron",
  "meta.root_namespace":"testnamespace",
  "meta.caller_id":"/api/:version/internal/post_receive"
}`

	expectedTime := time.Date(2018, 10, 29, 12, 49, 42, int(123*time.Millisecond), time.UTC)
	expectedEvent := &API{
		Time:                (*timestamp.RFC3339)(&expectedTime),
		Severity:            aws.String("INFO"),
		DurationSeconds:     aws.Float32(709.08),
		DBDurationSeconds:   aws.Float32(14.59),
		ViewDurationSeconds: aws.Float32(694.49),
		Status:              aws.Int16(200),
		Method:              aws.String("GET"),
		Path:                aws.String("/api/v4/projects"),
		Params: []QueryParam{
			{Key: aws.String("action"), Value: []byte("\"git-upload-pack\"")},
			{Key: aws.String("changes"), Value: []byte("\"_any\"")},
			{Key: aws.String("key_id"), Value: []byte("\"secret\"")},
			{Key: aws.String("secret_token"), Value: []byte("\"[FILTERED]\"")},
		},
		Host:                  aws.String("localhost"),
		UserAgent:             aws.String("Ruby"),
		Route:                 aws.String("/api/:version/projects"),
		RemoteIP:              aws.String("::1"),
		UserID:                aws.Int64(1),
		UserName:              aws.String("root"),
		GitalyCalls:           aws.Int(30),
		GitalyDurationSeconds: aws.Float32(5.36),
		QueueDuration:         aws.Float32(100.31),
		CorrelationID:         aws.String("895c51dc-96c8-4f18-8be4-65252b17a324"),
		MetaCallerID:          aws.String("/api/:version/internal/post_receive"),
		MetaProject:           aws.String("testuser/jumbotron"),
		MetaRootNamespace:     aws.String("testnamespace"),
		MetaUser:              aws.String("testuser"),
		RedisCalls:            aws.Int(10),
		RedisDurationSeconds:  aws.Float32(5.1),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.API")
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.RemoteIP)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkGitLabAPI(t, log, expectedEvent)
}
func TestGitLabAPIType(t *testing.T) {
	parser := (&APIParser{}).New()
	require.Equal(t, "GitLab.API", parser.LogType())
}

func TestGitLabAPISamples(t *testing.T) {
	samples := testutil.MustReadFileJSONLines("testdata/apilog_samples.jsonl")
	parser := (&APIParser{}).New()
	railsParser := (&ProductionParser{}).New()
	for i, sample := range samples {
		_, err := parser.Parse(sample)
		assert.NoErrorf(t, err, "failed to parse line %d", i)
		_, err = railsParser.Parse(sample)
		assert.Errorf(t, err, "line %d matches Production", i)
	}
}

func checkGitLabAPI(t *testing.T, log string, expectedEvent *API) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&APIParser{}).New()
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
	parserFail := (&ProductionParser{}).New()
	nilEvents, err := parserFail.Parse(log)
	require.Error(t, err)
	require.Nil(t, nilEvents)
}
