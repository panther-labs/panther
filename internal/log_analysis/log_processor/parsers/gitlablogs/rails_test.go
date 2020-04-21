package gitlablogs

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

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

func TestGitLabRails(t *testing.T) {
	// nolint:lll
	log := `{
  "method":"GET",
  "path":"/gitlab/gitlab-foss/issues/1234",
  "format":"html",
  "controller":"Projects::IssuesController",
  "action":"show",
  "status":200,
  "duration":229.03,
  "view":174.07,
  "db":13.24,
  "time":"2017-08-08T20:15:54.821Z",
  "params":[{"key":"param_key","value":"param_value"}],
  "remote_ip":"18.245.0.1",
  "user_id":1,
  "username":"admin",
  "gitaly_calls":76,
  "gitaly_duration":7.41,
  "queue_duration": 112.47
}`

	expectedTime := time.Date(2017, 8, 8, 20, 15, 54, int(821*time.Millisecond), time.UTC)
	expectedEvent := &Rails{
		Time:       (*timestamp.RFC3339)(&expectedTime),
		Method:     aws.String("GET"),
		Path:       aws.String("/gitlab/gitlab-foss/issues/1234"),
		Format:     aws.String("html"),
		Controller: aws.String("Projects::IssuesController"),
		Action:     aws.String("show"),
		Status:     aws.Int(200),
		Duration:   aws.Float32(229.03),
		View:       aws.Float32(174.07),
		DB:         aws.Float32(13.24),
		Params: []QueryParam{
			{Key: aws.String("param_key"), Value: aws.String("param_value")},
		},
		RemoteIP:       aws.String("18.245.0.1"),
		UserID:         aws.Int64(1),
		UserName:       aws.String("admin"),
		GitalyCalls:    aws.Int(76),
		GitalyDuration: aws.Float32(7.41),
		QueueDuration:  aws.Float32(112.47),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Rails")
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.RemoteIP)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkGitLabRails(t, log, expectedEvent)
}
func TestGitLabRailsException(t *testing.T) {
	log := `{
  "method": "GET",
  "path": "/admin",
  "format": "html",
  "controller": "Admin::DashboardController",
  "action": "index",
  "status": 500,
  "duration": 2584.11,
  "view": 0,
  "db": 9.21,
  "time": "2019-11-14T13:12:46.156Z",
  "params": [],
  "remote_ip": "127.0.0.1",
  "user_id": 1,
  "username": "root",
  "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0",
  "queue_duration": 274.35,
  "correlation_id": "KjDVUhNvvV3",
  "cpu_s": 2.837645135999999,
  "exception.class": "NameError",
  "exception.message": "undefined local variable or method 'adsf' for #<Admin::DashboardController:0x00007ff3c9648588>",
  "exception.backtrace": [
    "app/controllers/admin/dashboard_controller.rb:11:in 'index'",
    "ee/app/controllers/ee/admin/dashboard_controller.rb:14:in 'index'",
    "ee/lib/gitlab/ip_address_state.rb:10:in 'with'",
    "ee/app/controllers/ee/application_controller.rb:43:in 'set_current_ip_address'",
    "lib/gitlab/session.rb:11:in 'with_session'",
    "app/controllers/application_controller.rb:450:in 'set_session_storage'",
    "app/controllers/application_controller.rb:444:in 'set_locale'",
    "ee/lib/gitlab/jira/middleware.rb:19:in 'call'"
  ]
}`

	expectedTime := time.Date(2019, 11, 14, 13, 12, 46, int(156*time.Millisecond), time.UTC)
	expectedEvent := &Rails{
		Time:             (*timestamp.RFC3339)(&expectedTime),
		Method:           aws.String("GET"),
		Path:             aws.String("/admin"),
		Format:           aws.String("html"),
		Controller:       aws.String("Admin::DashboardController"),
		Action:           aws.String("index"),
		Status:           aws.Int(500),
		Duration:         aws.Float32(2584.11),
		View:             aws.Float32(0),
		DB:               aws.Float32(9.21),
		Params:           []QueryParam{},
		RemoteIP:         aws.String("127.0.0.1"),
		UserID:           aws.Int64(1),
		UserName:         aws.String("root"),
		UserAgent:        aws.String("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0"),
		QueueDuration:    aws.Float32(274.35),
		CorrelationID:    aws.String("KjDVUhNvvV3"),
		CPUSeconds:       aws.Float32(2.837645135999999),
		ExceptionClass:   aws.String("NameError"),
		ExceptionMessage: aws.String("undefined local variable or method 'adsf' for #<Admin::DashboardController:0x00007ff3c9648588>"),
		ExceptionBacktrace: []string{
			"app/controllers/admin/dashboard_controller.rb:11:in 'index'",
			"ee/app/controllers/ee/admin/dashboard_controller.rb:14:in 'index'",
			"ee/lib/gitlab/ip_address_state.rb:10:in 'with'",
			"ee/app/controllers/ee/application_controller.rb:43:in 'set_current_ip_address'",
			"lib/gitlab/session.rb:11:in 'with_session'",
			"app/controllers/application_controller.rb:450:in 'set_session_storage'",
			"app/controllers/application_controller.rb:444:in 'set_locale'",
			"ee/lib/gitlab/jira/middleware.rb:19:in 'call'",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Rails")
	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.RemoteIP)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkGitLabRails(t, log, expectedEvent)
}
func TestGitLabRailsType(t *testing.T) {
	parser := (&RailsParser{}).New()
	require.Equal(t, "GitLab.Rails", parser.LogType())
}

func checkGitLabRails(t *testing.T, log string, expectedEvent *Rails) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&RailsParser{}).New()
	events, err := parser.Parse(log)

	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
