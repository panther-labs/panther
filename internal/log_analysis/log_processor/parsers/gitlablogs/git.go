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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// TypeGit is the log type of Git log records
const TypeGit = PantherPrefix + ".Git"

// GitDesc describes the Git log record
var GitDesc = `GitLab log file containing all failed requests from GitLab to Git repositories.
Reference: https://docs.gitlab.com/ee/administration/logs.html#git_jsonlog`

// Git is a a GitLab log line from a failed interaction with git
type Git struct {
	Severity      *string            `json:"severity" validate:"required" description:"The log level"`
	Time          *timestamp.RFC3339 `json:"time" validate:"required" description:"The event timestamp"`
	CorrelationID *string            `json:"correlation_id,omitempty" description:"Unique id across logs"`
	Message       *string            `json:"message" validate:"required" description:"The error message from git"`

	parsers.PantherLog
}

// GitParser parses gitlab rails logs
type GitParser struct{}

var _ parsers.LogParser = (*GitParser)(nil)

// New creates a new parser
func (p *GitParser) New() parsers.LogParser {
	return &GitParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *GitParser) Parse(log string) ([]*parsers.PantherLog, error) {
	gitlabGit := Git{}

	err := jsoniter.UnmarshalFromString(log, &gitlabGit)
	if err != nil {
		return nil, err
	}

	gitlabGit.updatePantherFields(p)

	if err := parsers.Validator.Struct(gitlabGit); err != nil {
		return nil, err
	}

	return gitlabGit.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *GitParser) LogType() string {
	return TypeGit
}

func (event *Git) updatePantherFields(p *GitParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
}
