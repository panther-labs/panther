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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const (
	// TypeGit is the log type of Git log records
	TypeGit = PantherPrefix + ".Git"

	// GitDesc describes the Git log record
	GitDesc = `GitLab log file containing all failed requests from GitLab to Git repositories.
Reference: https://docs.gitlab.com/ee/administration/logs.html#git_jsonlog`
)

func init() {
	parsers.MustRegister(parsers.LogType{
		Name:        TypeGit,
		Description: GitDesc,
		Schema: struct {
			Git
			parsers.PantherLog
		}{},
		NewParser: NewGitParser,
	})
}

// Git is a a GitLab log line from a failed interaction with git
type Git struct {
	Severity      *string            `json:"severity" validate:"required" description:"The log level"`
	Time          *timestamp.RFC3339 `json:"time" validate:"required" description:"The event timestamp"`
	CorrelationID *string            `json:"correlation_id,omitempty" description:"Unique id across logs"`
	Message       *string            `json:"message" validate:"required" description:"The error message from git"`
}

// GitParser parses gitlab rails logs
type GitParser struct{}

var _ parsers.Parser = (*GitParser)(nil)

// New creates a new parser
func NewGitParser() parsers.Parser {
	return &GitParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *GitParser) Parse(log string) ([]*parsers.PantherLogJSON, error) {
	return parsers.QuickParseJSON(&Git{}, log)
}

// LogType returns the log type supported by this parser
func (p *GitParser) LogType() string {
	return TypeGit
}

func (event *Git) PantherEvent() *parsers.PantherEvent {
	return parsers.NewEvent(TypeGit, event.Time.UTC())
}
