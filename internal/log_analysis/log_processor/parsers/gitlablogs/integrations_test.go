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

func TestIntegrationsError(t *testing.T) {
	log := `{
  "severity":"ERROR",
  "time":"2018-09-06T14:56:20.439Z",
  "service_class":"JiraService",
  "project_id":8,
  "project_path":"h5bp/html5-boilerplate",
  "message":"Error sending message",
  "client_url":"http://jira.gitlap.com:8080",
  "error":"execution expired"
}`

	expectedTime := time.Date(2018, 9, 6, 14, 56, 20, int(439*time.Millisecond), time.UTC)
	expectedEvent := &Integrations{
		Severity:     aws.String("ERROR"),
		Time:         (*timestamp.RFC3339)(&expectedTime),
		ServiceClass: aws.String("JiraService"),
		ProjectID:    aws.Int64(8),
		ProjectPath:  aws.String("h5bp/html5-boilerplate"),
		Message:      aws.String("Error sending message"),
		ClientURL:    aws.String("http://jira.gitlap.com:8080"),
		Error:        aws.String("execution expired"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Integrations")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkIntegrations(t, log, expectedEvent)
}
func TestIntegrations(t *testing.T) {
	log := `{
  "severity":"INFO",
  "time":"2018-09-06T17:15:16.365Z",
  "service_class":"JiraService",
  "project_id":3,
  "project_path":"namespace2/project2",
  "message":"Successfully posted",
  "client_url":"http://jira.example.com"
}`

	expectedTime := time.Date(2018, 9, 6, 17, 15, 16, int(365*time.Millisecond), time.UTC)

	expectedEvent := &Integrations{
		Severity:     aws.String("INFO"),
		Time:         (*timestamp.RFC3339)(&expectedTime),
		ServiceClass: aws.String("JiraService"),
		ProjectID:    aws.Int64(3),
		ProjectPath:  aws.String("namespace2/project2"),
		Message:      aws.String("Successfully posted"),
		ClientURL:    aws.String("http://jira.example.com"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Integrations")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkIntegrations(t, log, expectedEvent)
}
func TestGitLabIntegrationsType(t *testing.T) {
	parser := (&IntegrationsParser{}).New()
	require.Equal(t, "GitLab.Integrations", parser.LogType())
}

func checkIntegrations(t *testing.T, log string, expectedEvent *Integrations) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&IntegrationsParser{}).New()

	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
