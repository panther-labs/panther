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

func TestGitLabProduction(t *testing.T) {
	// nolint:lll
	log := `
{
  "method":"GET",
  "path":"/gitlab/gitlab-foss/issues/1234",
  "format":"html",
  "controller":"Projects::IssuesController",
  "action":"show",
  "status":200,
  "time":"2017-08-08T20:15:54.821Z",
  "params":[{"key":"param_key","value":"param_value"}],
  "remote_ip":"18.245.0.1",
  "user_id":1,
  "username":"admin",
  "queue_duration_s":0.0,
  "gitaly_calls":16,
  "gitaly_duration_s":0.16,
  "redis_calls":115,
  "redis_duration_s":0.13,
  "redis_read_bytes":1507378,
  "redis_write_bytes":2920,
  "correlation_id":"O1SdybnnIq7",
  "cpu_s":17.50,
  "db_duration_s":0.08,
  "view_duration_s":2.39,
  "duration_s":20.54
}`

	expectedTime := time.Date(2017, 8, 8, 20, 15, 54, int(821*time.Millisecond), time.UTC)
	expectedEvent := &Production{
		Time:            (*timestamp.RFC3339)(&expectedTime),
		Method:          aws.String("GET"),
		Path:            aws.String("/gitlab/gitlab-foss/issues/1234"),
		Format:          aws.String("html"),
		Controller:      aws.String("Projects::IssuesController"),
		Action:          aws.String("show"),
		Status:          aws.Int(200),
		DurationSeconds: aws.Float32(20.54),
		CorrelationID:   aws.String("O1SdybnnIq7"),
		Params: []QueryParam{
			{Key: aws.String("param_key"), Value: []byte("\"param_value\"")},
		},
		RemoteIP:              aws.String("18.245.0.1"),
		UserID:                aws.Int64(1),
		UserName:              aws.String("admin"),
		GitalyCalls:           aws.Int(16),
		GitalyDurationSeconds: aws.Float32(0.16),
		QueueDurationSeconds:  aws.Float32(0),
		CPUSeconds:            aws.Float32(17.5),
		DBDurationSeconds:     aws.Float32(0.08),
		RedisCalls:            aws.Int(115),
		RedisDurationSeconds:  aws.Float32(0.13),
		RedisReadBytes:        aws.Int64(1507378),
		RedisWriteBytes:       aws.Int64(2920),
		ViewDurationSeconds:   aws.Float32(2.39),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Production")
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.RemoteIP)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkGitLabProduction(t, log, expectedEvent)
}
func TestGitLabProductionException(t *testing.T) {
	log := `
{
  "method": "GET",
  "path": "/admin",
  "format": "html",
  "controller": "Admin::DashboardController",
  "action": "index",
  "status": 500,
  "time": "2019-11-14T13:12:46.156Z",
  "params": [],
  "remote_ip": "127.0.0.1",
  "user_id": 1,
  "username": "root",
  "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0",
  "queue_duration": 274.35,
  "correlation_id": "KjDVUhNvvV3",
  "queue_duration_s":0.0,
  "gitaly_calls":16,
  "gitaly_duration_s":0.16,
  "redis_calls":115,
  "redis_duration_s":0.13,
  "correlation_id":"O1SdybnnIq7",
  "cpu_s":17.50,
  "db_duration_s":0.08,
  "view_duration_s":2.39,
  "duration_s":20.54,
  "exception.class": "NameError",
  "exception.message": "undefined local variable or method for #<Admin::DashboardController:0x00007ff3c9648588>",
	"exception.backtrace": [
		"ee/lib/gitlab/jira/middleware.rb:19:in call"]
}`

	expectedTime := time.Date(2019, 11, 14, 13, 12, 46, int(156*time.Millisecond), time.UTC)
	expectedEvent := &Production{
		Time:                  (*timestamp.RFC3339)(&expectedTime),
		Method:                aws.String("GET"),
		Path:                  aws.String("/admin"),
		Format:                aws.String("html"),
		Controller:            aws.String("Admin::DashboardController"),
		Action:                aws.String("index"),
		Status:                aws.Int(500),
		DurationSeconds:       aws.Float32(20.54),
		Params:                []QueryParam{},
		RemoteIP:              aws.String("127.0.0.1"),
		UserID:                aws.Int64(1),
		UserName:              aws.String("root"),
		UserAgent:             aws.String("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0"),
		QueueDurationSeconds:  aws.Float32(0),
		CorrelationID:         aws.String("O1SdybnnIq7"),
		CPUSeconds:            aws.Float32(17.5),
		DBDurationSeconds:     aws.Float32(0.08),
		GitalyCalls:           aws.Int(16),
		GitalyDurationSeconds: aws.Float32(0.16),
		RedisCalls:            aws.Int(115),
		RedisDurationSeconds:  aws.Float32(0.13),
		ViewDurationSeconds:   aws.Float32(2.39),

		ExceptionClass:   aws.String("NameError"),
		ExceptionMessage: aws.String("undefined local variable or method for #<Admin::DashboardController:0x00007ff3c9648588>"),
		ExceptionBacktrace: []string{
			"ee/lib/gitlab/jira/middleware.rb:19:in call",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Production")
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.RemoteIP)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkGitLabProduction(t, log, expectedEvent)
}
func TestGitLabProductionType(t *testing.T) {
	parser := (&ProductionParser{}).New()
	require.Equal(t, "GitLab.Production", parser.LogType())
}

func TestGitLabProductionSamples(t *testing.T) {
	samples := testutil.MustReadFileJSONLines("testdata/productionlog_samples.jsonl")
	parser := (&ProductionParser{}).New()
	for i, sample := range samples {
		_, err := parser.Parse(sample)
		assert.NoErrorf(t, err, "failed to parse line %d", i)
	}
}

func checkGitLabProduction(t *testing.T, log string, expectedEvent *Production) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&ProductionParser{}).New()
	events, err := parser.Parse(log)

	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
