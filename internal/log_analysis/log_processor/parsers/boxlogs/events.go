package boxlogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeEvent = "Box.Event"

type EventParser struct{}

func NewEventParser() *EventParser {
	return &EventParser{}
}

func (p *EventParser) New() parsers.LogParser {
	return p
}
func (p *EventParser) LogType() string {
	return TypeEvent
}
func (p *EventParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := Event{}
	if err := jsoniter.UnmarshalFromString(log, &event); err != nil {
		return nil, err
	}
	event.updatePantherFields(&event.PantherLog)
	if err := parsers.Validator.Struct(&event); err != nil {
		return nil, err
	}
	return event.Logs(), nil
}

// nolint:lll
type Event struct {
	AdditionalDetails *jsoniter.RawMessage `json:"additional_details,omitempty" description:"This object provides additional information about the event if available."`
	CreatedAt         *timestamp.RFC3339   `json:"created_at,omitempty" description:"The timestamp of the event"`
	CreatedBy         *UserMini            `json:"created_by,omitempty" description:"The user that performed the action represented by the event."`
	EventID           string               `json:"event_id" validate:"required" description:"The ID of the event object. You can use this to detect duplicate events"`
	EventType         string               `json:"event_type" validate:"required" description:"The event type that triggered this event"`
	Type              string               `json:"type" validate:"required,eq=event" description:"The object type (always 'event')"`
	Source            EventSourceOrUser    `json:"source" validate:"required" description:"The item that triggered this event"`
	SessionID         null.String          `json:"session_id,omitempty" description:"The event type that triggered this event"`
	IPAddress         null.String          `json:"ip_address,omitempty" description:"The IP address the request was made from."`

	parsers.PantherLog
}

func (e *Event) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeEvent, e.CreatedAt, e)
	if e.IPAddress.Exists {
		p.AppendAnyIPAddress(e.IPAddress.Value)
	}
}

// nolint:lll
// The fields are declared 'omitempty' on purpose so we can use them in the EventSourceOrUser enum
type UserMini struct {
	ID    string `json:"id,omitempty" description:"The unique identifier for this object"`
	Type  string `json:"type,omitempty" validate:"omitempty,eq=user" description:"The object type (always 'user')"`
	Login string `json:"login,omitempty" description:"The primary email address of this user"`
	Name  string `json:"name,omitempty" description:"The display name of this user" `
}
type EventSourceOrUser struct {
	UserMini
	EventSource
}

// nolint:lll
// The fields are declared 'omitempty' on purpose so we can use them in the EventSourceOrUser enum
type EventSource struct {
	ItemID   string      `json:"item_id,omitempty" description:"The unique identifier that represents the item."`
	ItemName string      `json:"item_name,omitempty" description:"The name of the item."`
	ItemType string      `json:"item_type,omitempty" description:"The type of the item that the event represents. Can be file or folder."`
	OwnedBy  *UserMini   `json:"owned_by,omitempty" description:"The user who owns this item."`
	Parent   *FolderMini `json:"parent,omitempty" description:"The optional folder that this folder is located within."`
}

// nolint:lll
type FolderMini struct {
	Etag       string `json:"etag" description:"The HTTP etag of this folder."`
	ID         string `json:"id" description:"The unique identifier that represent a folder."`
	Type       string `json:"type" validate:"required,eq=folder" description:"The type of the object (always 'folder')"`
	Name       string `json:"name" description:"The name of the folder"`
	SequenceID string `json:"sequence_id,omitempty" description:"A numeric identifier that represents the most recent user event that has been applied to this item."`
}
