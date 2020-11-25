package gsuitelogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// nolint:lll
type Reports struct {
	ID          *ID     `json:"id" validate:"required" description:"Unique identifier for each activity record."`
	Actor       *Actor  `json:"actor,omitempty" description:"User doing the action."`
	Kind        *string `json:"kind" validate:"eq=admin#reports#activity" description:"The type of API resource. For an activity report, the value is reports#activities."`
	OwnerDomain *string `json:"ownerDomain,omitempty" description:"This is the domain that is affected by the report's event. For example domain of Admin console or the Drive application's document owner."`
	IPAddress   *string `json:"ipAddress,omitempty" description:"IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into G Suite which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6."`
	Events      []Event `json:"events,omitempty" description:"Activity events in the report."`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// nolint:lll
type Actor struct {
	Email      *string `json:"email,omitempty" description:"The primary email address of the actor. May be absent if there is no email address associated with the actor."`
	ProfileID  *string `json:"profileId,omitempty" description:"The unique G Suite profile ID of the actor. May be absent if the actor is not a G Suite user."`
	CallerType *string `json:"callerType,omitempty" description:"The type of actor."`
	Key        *string `json:"key,omitempty" description:"Only present when callerType is KEY. Can be the consumer_key of the requestor for OAuth 2LO API requests or an identifier for robot accounts."`
}

// nolint:lll
type ID struct {
	ApplicationName *string            `json:"applicationName,omitempty" description:"Application name to which the event belongs."`
	CustomerID      *string            `json:"customerId,omitempty" description:"The unique identifier for a G suite account."`
	Time            *timestamp.RFC3339 `json:"time,omitempty" description:"Time of occurrence of the activity."`
	UniqueQualifier *string            `json:"uniqueQualifier,omitempty" description:"Unique qualifier if multiple events have the same time."`
}

// nolint:lll
type Event struct {
	Type       *string     `json:"type,omitempty" description:"Type of event. The G Suite service or feature that an administrator changes is identified in the type property which identifies an event using the eventName property. For a full list of the API's type categories, see the list of event names for various applications above in applicationName."`
	Name       *string     `json:"name,omitempty" description:"Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific G Suite service or feature which the API organizes into types of events."`
	Parameters []Parameter `json:"parameters,omitempty" description:"Parameter value pairs for various applications. For more information about eventName parameters, see the list of event names for various applications above in applicationName."`
}

// nolint:lll
type Parameter struct {
	Name              *string               `json:"name,omitempty" description:"The name of the parameter."`
	Value             *string               `json:"value,omitempty" description:"String value of the parameter."`
	IntValue          *numerics.Int64       `json:"intValue,omitempty" description:"Integer value of the parameter."`
	BoolValue         *bool                 `json:"boolValue,omitempty" description:"Boolean value of the parameter."`
	MultiValue        []string              `json:"multiValue,omitempty" description:"String values of the parameter."`
	MultiIntValue     []numerics.Int64      `json:"multiIntValue,omitempty" description:"Integer values of the parameter."`
	MessageValue      *jsoniter.RawMessage  `json:"messageValue,omitempty" description:"Nested parameter value pairs associated with this parameter. Complex value type for a parameter are returned as a list of parameter values. For example, the address parameter may have a value as [{parameter: [{name: city, value: abc}]}]"`
	MultiMessageValue []jsoniter.RawMessage `json:"multiMessageValue,omitempty" description:"List of messageValue objects."`
}

// ReportsParser parses GSuite Reports logs
type ReportsParser struct{}

var _ parsers.LogParser = (*ReportsParser)(nil)

func (p *ReportsParser) New() parsers.LogParser {
	return NewReportsParser()
}

func NewReportsParser() *ReportsParser {
	return &ReportsParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ReportsParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := &Reports{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		return nil, err
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}

	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *ReportsParser) LogType() string {
	return TypeReports
}

func (event *Reports) updatePantherFields(p *ReportsParser) {
	event.SetCoreFields(p.LogType(), event.ID.Time, event)
	event.AppendAnyDomainNamePtrs(event.OwnerDomain)
	event.AppendAnyIPAddressPtr(event.IPAddress)
}
