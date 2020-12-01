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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// nolint:lll
type Reports struct {
	ID          *ID               `json:"id" validate:"required" description:"Unique identifier for each activity record."`
	Actor       *Actor            `json:"actor" description:"User doing the action."`
	Kind        pantherlog.String `json:"kind" validate:"eq=admin#reports#activity" description:"The type of API resource. For an activity report, the value is reports#activities."`
	OwnerDomain pantherlog.String `json:"ownerDomain" panther:"domain" description:"This is the domain that is affected by the report's event. For example domain of Admin console or the Drive application's document owner."`
	IPAddress   pantherlog.String `json:"ipAddress" panther:"ip" description:"IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into G Suite which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6."`
	Events      []Event           `json:"events" description:"Activity events in the report."`
}

// nolint:lll
type Actor struct {
	Email      pantherlog.String `json:"email" panther:"email" description:"The primary email address of the actor. May be absent if there is no email address associated with the actor."`
	ProfileID  pantherlog.String `json:"profileId" description:"The unique G Suite profile ID of the actor. May be absent if the actor is not a G Suite user."`
	CallerType pantherlog.String `json:"callerType" description:"The type of actor."`
	Key        pantherlog.String `json:"key" description:"Only present when callerType is KEY. Can be the consumer_key of the requestor for OAuth 2LO API requests or an identifier for robot accounts."`
}

// nolint:lll
type ID struct {
	ApplicationName pantherlog.String `json:"applicationName" description:"Application name to which the event belongs."`
	CustomerID      pantherlog.String `json:"customerId" description:"The unique identifier for a G suite account."`
	Time            pantherlog.Time   `json:"time" event_time:"true" tcodec:"rfc3339" description:"Time of occurrence of the activity."`
	UniqueQualifier pantherlog.String `json:"uniqueQualifier" description:"Unique qualifier if multiple events have the same time."`
}

// nolint:lll
type Event struct {
	Type       pantherlog.String `json:"type" description:"Type of event. The G Suite service or feature that an administrator changes is identified in the type property which identifies an event using the eventName property. For a full list of the API's type categories, see the list of event names for various applications above in applicationName."`
	Name       pantherlog.String `json:"name" description:"Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific G Suite service or feature which the API organizes into types of events."`
	Parameters []Parameter       `json:"parameters" description:"Parameter value pairs for various applications. For more information about eventName parameters, see the list of event names for various applications above in applicationName."`
}

// nolint:lll
type Parameter struct {
	Name              pantherlog.String       `json:"name" description:"The name of the parameter."`
	Value             pantherlog.String       `json:"value" description:"String value of the parameter."`
	IntValue          pantherlog.Int64        `json:"intValue" description:"Integer value of the parameter."`
	BoolValue         pantherlog.Bool         `json:"boolValue" description:"Boolean value of the parameter."`
	MultiValue        []string                `json:"multiValue" description:"String values of the parameter."`
	MultiIntValue     []pantherlog.Int64      `json:"multiIntValue" description:"Integer values of the parameter."`
	MessageValue      pantherlog.RawMessage   `json:"messageValue" description:"Nested parameter value pairs associated with this parameter. Complex value type for a parameter are returned as a list of parameter values. For example, the address parameter may have a value as [{parameter: [{name: city, value: abc}]}]"`
	MultiMessageValue []pantherlog.RawMessage `json:"multiMessageValue" description:"List of messageValue objects."`
}
