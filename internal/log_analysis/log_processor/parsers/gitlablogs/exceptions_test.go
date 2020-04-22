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

func TestExceptionsParser(t *testing.T) {
	log := `{
		"severity": "ERROR",
		"time": "2019-12-17T11:49:29.485Z",
		"correlation_id": "AbDVUrrTvM1",
		"extra.server": {
			"os": {
				"name": "Darwin",
				"version": "Darwin Kernel Version 19.2.0",
				"build": "19.2.0"
			},
			"runtime": {
				"name": "ruby",
				"version": "ruby 2.6.5p114 (2019-10-01 revision 67812) [x86_64-darwin18]"
			}
		},
		"extra.project_id": 55,
		"extra.relation_key": "milestones",
		"extra.relation_index": 1,
		"exception.class": "NoMethodError",
		"exception.message": "undefined method 'strong_memoize' for #<Gitlab::ImportExport::RelationFactory:0x00007fb5d917c4b0>",
		"exception.backtrace": [
			"lib/gitlab/import_export/relation_factory.rb:329:in 'unique_relation?'",
			"lib/gitlab/import_export/relation_factory.rb:345:in 'find_or_create_object!'"
		]
	}`

	expectedTime := time.Date(2019, 12, 17, 11, 49, 29, int(485*time.Millisecond), time.UTC)
	expectedEvent := &Exceptions{
		Severity:      aws.String("ERROR"),
		Time:          (*timestamp.RFC3339)(&expectedTime),
		CorrelationID: aws.String("AbDVUrrTvM1"),
		ExtraServer: &ExtraServer{
			OS: &ServerOS{
				Name:    aws.String("Darwin"),
				Version: aws.String("Darwin Kernel Version 19.2.0"),
				Build:   aws.String("19.2.0"),
			},
			Runtime: &ServerRuntime{
				Name:    aws.String("ruby"),
				Version: aws.String("ruby 2.6.5p114 (2019-10-01 revision 67812) [x86_64-darwin18]"),
			},
		},
		ExtraProjectID:     aws.Int64(55),
		ExtraRelationKey:   aws.String("milestones"),
		ExtraRelationIndex: aws.Int64(1),
		ExceptionClass:     aws.String("NoMethodError"),
		ExceptionMessage:   aws.String("undefined method 'strong_memoize' for #<Gitlab::ImportExport::RelationFactory:0x00007fb5d917c4b0>"),
		ExceptionBacktrace: []string{
			"lib/gitlab/import_export/relation_factory.rb:329:in 'unique_relation?'",
			"lib/gitlab/import_export/relation_factory.rb:345:in 'find_or_create_object!'",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Exceptions")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkExceptions(t, log, expectedEvent)
}
func TestExceptionsType(t *testing.T) {
	parser := (&ExceptionsParser{}).New()
	require.Equal(t, "GitLab.Exceptions", parser.LogType())
}

func checkExceptions(t *testing.T, log string, expectedEvent *Exceptions) {
	t.Helper()
	expectedEvent.SetEvent(expectedEvent)
	parser := &ExceptionsParser{}
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
