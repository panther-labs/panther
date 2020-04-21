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

func TestAuditParser(t *testing.T) {
	log := `{
		"severity":"INFO",
		"time":"2018-10-17T17:38:22.523Z",
		"author_id":3,
		"entity_id":2,
		"entity_type":"Project",
		"change":"visibility",
		"from":"Private",
		"to":"Public",
		"author_name":"John Doe4",
		"target_id":2,
		"target_type":"Project",
		"target_details":"namespace2/project2"
	}`

	expectedTime := time.Date(2018, 10, 17, 17, 38, 22, int(523*time.Millisecond), time.UTC)
	expectedEvent := &Audit{
		Severity:      aws.String("INFO"),
		Time:          (*timestamp.RFC3339)(&expectedTime),
		AuthorID:      aws.Int64(3),
		EntityID:      aws.Int64(2),
		EntityType:    aws.String("Project"),
		Change:        aws.String("visibility"),
		From:          aws.String("Private"),
		To:            aws.String("Public"),
		AuthorName:    aws.String("John Doe4"),
		TargetID:      aws.Int64(2),
		TargetType:    aws.String("Project"),
		TargetDetails: aws.String("namespace2/project2"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Audit")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkAudit(t, log, expectedEvent)
}
func TestAuditType(t *testing.T) {
	parser := (&AuditParser{}).New()
	require.Equal(t, "GitLab.Audit", parser.LogType())
}

func checkAudit(t *testing.T, log string, expectedEvent *Audit) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&AuditParser{}).New()
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
