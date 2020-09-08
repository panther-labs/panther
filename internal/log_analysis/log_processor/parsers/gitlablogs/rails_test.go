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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
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
		Method:          box.String("GET"),
		Path:            box.String("/gitlab/gitlab-foss/issues/1234"),
		Format:          box.String("html"),
		Controller:      box.String("Projects::IssuesController"),
		Action:          box.String("show"),
		Status:          box.Int(200),
		DurationSeconds: box.Float32(20.54),
		CorrelationID:   box.String("O1SdybnnIq7"),
		Params: []QueryParam{
			{Key: box.String("param_key"), Value: []byte("\"param_value\"")},
		},
		RemoteIP:              box.String("18.245.0.1"),
		UserID:                box.Int64(1),
		UserName:              box.String("admin"),
		GitalyCalls:           box.Int(16),
		GitalyDurationSeconds: box.Float32(0.16),
		QueueDurationSeconds:  box.Float32(0),
		CPUSeconds:            box.Float32(17.5),
		DBDurationSeconds:     box.Float32(0.08),
		RedisCalls:            box.Int(115),
		RedisDurationSeconds:  box.Float32(0.13),
		RedisReadBytes:        box.Int64(1507378),
		RedisWriteBytes:       box.Int64(2920),
		ViewDurationSeconds:   box.Float32(2.39),
	}

	// panther fields
	expectedEvent.PantherLogType = box.String("GitLab.Production")
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
		Method:                box.String("GET"),
		Path:                  box.String("/admin"),
		Format:                box.String("html"),
		Controller:            box.String("Admin::DashboardController"),
		Action:                box.String("index"),
		Status:                box.Int(500),
		DurationSeconds:       box.Float32(20.54),
		Params:                []QueryParam{},
		RemoteIP:              box.String("127.0.0.1"),
		UserID:                box.Int64(1),
		UserName:              box.String("root"),
		UserAgent:             box.String("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0"),
		QueueDurationSeconds:  box.Float32(0),
		CorrelationID:         box.String("O1SdybnnIq7"),
		CPUSeconds:            box.Float32(17.5),
		DBDurationSeconds:     box.Float32(0.08),
		GitalyCalls:           box.Int(16),
		GitalyDurationSeconds: box.Float32(0.16),
		RedisCalls:            box.Int(115),
		RedisDurationSeconds:  box.Float32(0.13),
		ViewDurationSeconds:   box.Float32(2.39),

		ExceptionClass:   box.String("NameError"),
		ExceptionMessage: box.String("undefined local variable or method for #<Admin::DashboardController:0x00007ff3c9648588>"),
		ExceptionBacktrace: []string{
			"ee/lib/gitlab/jira/middleware.rb:19:in call",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = box.String("GitLab.Production")
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.RemoteIP)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkGitLabProduction(t, log, expectedEvent)
}

func TestGitLabProductionRedirect(t *testing.T) {
	log := `
{
  "method":"GET",
  "path":"/index.php",
  "format":null,
  "controller":"ApplicationController",
  "action":"route_not_found",
  "status":302,
  "location":"http://34.222.254.254/users/sign_in",
  "time":"2020-07-05T19:35:32.337Z",
  "params":[{"key":"vars","value":{"0":"md5","1":["HelloThinkPHP"]}}],
  "remote_ip":"195.54.254.254",
  "user_id":null,
  "username":null,
  "ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
  "queue_duration_s":0.007208,
  "correlation_id":"DScuWzVUYA5",
  "meta.caller_id":"ApplicationController#route_not_found",
  "redis_calls":1,
  "redis_duration_s":0.000292,
  "cpu_s":0.02,
  "db_duration_s":0.0,
  "view_duration_s":0.0,
  "duration_s":0.00341,
  "tag":"test"
}
`
	expectedTime := time.Date(2020, 7, 5, 19, 35, 32, int(337*time.Millisecond), time.UTC)
	expectedEvent := &Production{
		Time:            (*timestamp.RFC3339)(&expectedTime),
		Method:          box.String("GET"),
		Path:            box.String("/index.php"),
		Controller:      box.String("ApplicationController"),
		Action:          box.String("route_not_found"),
		Status:          box.Int(302),
		DurationSeconds: box.Float32(0.00341),
		Params: []QueryParam{
			{
				Key:   box.String("vars"),
				Value: []byte(`{"0":"md5","1":["HelloThinkPHP"]}`),
			},
		},
		RemoteIP:             box.String("195.54.254.254"),
		UserAgent:            box.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"),
		QueueDurationSeconds: box.Float32(0.007208),
		CorrelationID:        box.String("DScuWzVUYA5"),
		CPUSeconds:           box.Float32(0.02),
		DBDurationSeconds:    box.Float32(0.0),
		RedisCalls:           box.Int(1),
		RedisDurationSeconds: box.Float32(0.000292),
		ViewDurationSeconds:  box.Float32(0.0),
		MetaCallerID:         box.String("ApplicationController#route_not_found"),
		Location:             box.String("http://34.222.254.254/users/sign_in"),
	}

	// panther fields
	expectedEvent.PantherLogType = box.String("GitLab.Production")
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
	apiParser := (&APIParser{}).New()
	for i, sample := range samples {
		_, err := parser.Parse(sample)
		assert.NoErrorf(t, err, "failed to parse line %d", i)
		_, err = apiParser.Parse(sample)
		assert.Error(t, err, "Production log passes as API")
	}
}

func checkGitLabProduction(t *testing.T, log string, expectedEvent *Production) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&ProductionParser{}).New()
	events, err := parser.Parse(log)

	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
