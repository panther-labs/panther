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
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestGitLabAPI(t *testing.T) {
	// nolint:lll
	log := `{
  "time":"2018-10-29T12:49:42.123Z",
  "severity":"INFO",
  "duration":709.08,
  "db":14.59,
  "view":694.49,
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
  "queue_duration":100.31,
  "gitaly_calls":30,
  "gitaly_duration":5.36
}`

	expectedTime := time.Date(2018, 10, 29, 12, 49, 42, int(123*time.Millisecond), time.UTC)
	expectedEvent := &API{
		Time:     (*timestamp.RFC3339)(&expectedTime),
		Severity: aws.String("INFO"),
		Duration: aws.Float32(709.08),
		DB:       aws.Float32(14.59),
		View:     aws.Float32(694.49),
		Status:   aws.Int(200),
		Method:   aws.String("GET"),
		Path:     aws.String("/api/v4/projects"),
		Params: []QueryParam{
			{Key: aws.String("action"), Value: aws.String("git-upload-pack")},
			{Key: aws.String("changes"), Value: aws.String("_any")},
			{Key: aws.String("key_id"), Value: aws.String("secret")},
			{Key: aws.String("secret_token"), Value: aws.String("[FILTERED]")},
		},
		Host:           aws.String("localhost"),
		UserAgent:      aws.String("Ruby"),
		Route:          aws.String("/api/:version/projects"),
		RemoteIP:       aws.String("::1"),
		UserID:         aws.Int64(1),
		UserName:       aws.String("root"),
		GitalyCalls:    aws.Int(30),
		GitalyDuration: aws.Float32(5.36),
		QueueDuration:  aws.Float32(100.31),
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

func checkGitLabAPI(t *testing.T, log string, expectedEvent *API) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&APIParser{}).New()
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
