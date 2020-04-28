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

// nolint:lll
func TestGitParser(t *testing.T) {
	log := `{
		"severity":"ERROR",
		"time":"2019-07-19T22:16:12.528Z",
		"correlation_id":"FeGxww5Hj64",
		"message":"Command failed [1]: /usr/bin/git --git-dir=/Users/vsizov/gitlab-development-kit/gitlab/tmp/tests/gitlab-satellites/group184/gitlabhq/.git --work-tree=/Users/vsizov/gitlab-development-kit/gitlab/tmp/tests/gitlab-satellites/group184/gitlabhq merge --no-ff -mMerge branch 'feature_conflict' into 'feature' source/feature_conflict\n\nerror: failed to push some refs to '/Users/vsizov/gitlab-development-kit/repositories/gitlabhq/gitlab_git.git'"
	}`

	expectedTime := time.Date(2019, 7, 19, 22, 16, 12, int(528*time.Millisecond), time.UTC)

	expectedEvent := &Git{
		Severity:      aws.String("ERROR"),
		Time:          (*timestamp.RFC3339)(&expectedTime),
		CorrelationID: aws.String("FeGxww5Hj64"),
		Message:       aws.String("Command failed [1]: /usr/bin/git --git-dir=/Users/vsizov/gitlab-development-kit/gitlab/tmp/tests/gitlab-satellites/group184/gitlabhq/.git --work-tree=/Users/vsizov/gitlab-development-kit/gitlab/tmp/tests/gitlab-satellites/group184/gitlabhq merge --no-ff -mMerge branch 'feature_conflict' into 'feature' source/feature_conflict\n\nerror: failed to push some refs to '/Users/vsizov/gitlab-development-kit/repositories/gitlabhq/gitlab_git.git'"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("GitLab.Git")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkGit(t, log, expectedEvent)
}
func TestGitType(t *testing.T) {
	parser := (&GitParser{}).New()
	require.Equal(t, "GitLab.Git", parser.LogType())
}

func checkGit(t *testing.T, log string, expectedEvent *Git) {
	expectedEvent.SetEvent(expectedEvent)
	parser := (&GitParser{}).New()
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
