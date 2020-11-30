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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// Audit is a a GitLab log line from a failed interaction with git
// nolint: lll
type Audit struct {
	Severity      pantherlog.String `json:"severity" validate:"required" description:"The log level"`
	Time          pantherlog.Time   `json:"time" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The event timestamp"`
	AuthorID      pantherlog.Int64  `json:"author_id" validate:"required" description:"User id that made the change"`
	EntityID      pantherlog.Int64  `json:"entity_id" validate:"required" description:"Id of the entity that was modified"`
	EntityType    pantherlog.String `json:"entity_type" validate:"required" description:"Type of the modified entity"`
	Change        pantherlog.String `json:"change" validate:"required" description:"Type of change to the settings"`
	From          pantherlog.String `json:"from" validate:"required" description:"Old setting value"`
	To            pantherlog.String `json:"to" validate:"required" description:"New setting value"`
	AuthorName    pantherlog.String `json:"author_name" validate:"required" description:"Name of the user that made the change"`
	TargetID      pantherlog.Int64  `json:"target_id" validate:"required" description:"Target id of the modified setting"`
	TargetType    pantherlog.String `json:"target_type" validate:"required" description:"Target type of the modified setting"`
	TargetDetails pantherlog.String `json:"target_details" validate:"required" description:"Details of the target of the modified setting"`
}
