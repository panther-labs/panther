package crowdstrikelogs

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
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

const TypePrefix = "Crowdstrike"

// LogTypes exports all crowdstrike logs
func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must(TypePrefix,
	TypeDNSRequest,
	TypeNetworkConnect,
	TypeNetworkListen,
	TypeProcessRollup2,
	TypeSyntheticProcessRollup2,
	// Falcon Insight Special Raw Events
	TypeAIDMaster,
	TypeManagedAssets,
	TypeNotManagedAssets,
	// Falcon Discover Processed Events
	TypeUserInfo,
	TypeAppInfo,
	TypeUnknownEvent,
)

// WARNING: Remember to use mustRegisterCrowdstrikeEvent to add new events so known event names are up-to-date

// mustRegisterCrowdstrikeEvent validates that the event has an EventSimpleName field with a proper `validate` tag and
// updates the knownEventNames index so that the parsers for UnknownEvent can distinguish which events to pick.
func mustBuild(config logtypes.ConfigJSON) logtypes.Entry {
	event := config.NewEvent()
	typ := reflect.TypeOf(event)
	names, err := getEventSimpleName(typ)
	if err != nil {
		panic(err)
	}
	if len(names) == 0 {
		panic(fmt.Errorf(`no names for %s`, typ))
	}

	for _, name := range names {
		name := strings.TrimSpace(name)
		if _, duplicate := knownEventNames[name]; duplicate {
			panic(fmt.Errorf(`duplicate event simple name %q`, name))
		}
		knownEventNames[name] = true
	}
	return logtypes.MustBuild(config)
}

func getEventSimpleName(typ reflect.Type) ([]string, error) {
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("invalid event type %s", typ)
	}
	field, ok := typ.FieldByName(`EventSimpleName`)
	if !ok {
		return nil, fmt.Errorf("missing field EventSimpleName %s", typ)
	}
	validateTag := field.Tag.Get(`validate`)
	if name := strings.TrimPrefix(validateTag, "required,eq="); name != validateTag {
		return []string{name}, nil
	}
	if name := strings.TrimPrefix(validateTag, "required,oneof="); name != validateTag {
		return strings.Split(name, " "), nil
	}
	return nil, fmt.Errorf(`invalid validate tag %q`, validateTag)
}

// Common fields for all croudstrike events
// nolint:lll
type BaseEvent struct {
	Name           null.String `json:"name" validate:"required" description:"The event name"`
	AID            null.String `json:"aid" description:"The sensor ID. This value is unique to each installation of a Falcon sensor. When a sensor is updated or reinstalled, the host gets a new aid. In those situations, a single host could have multiple aid values over time."`
	AIP            null.String `json:"aip" panther:"ip" description:"The sensor’s IP, as seen from the CrowdStrike cloud. This is typically the public IP of the sensor. This helps determine the location of a computer, depending on your network." `
	CID            null.String `json:"cid" description:"CID"`
	ID             null.String `json:"id" description:"ID"`
	EventPlatform  null.String `json:"event_platform" description:"The platform the sensor was running on"`
	Timestamp      time.Time   `json:"timestamp" tcodec:"unix_ms" event_time:"true" description:"Timestamp when the event was received by the CrowdStrike cloud."`
	TimestampHuman time.Time   `json:"_time" tcodec:"layout=01/02/2006 15:04:05.999" description:"Timestamp when the event was received by the CrowdStrike cloud (human readable)"`

	ComputerName    null.String `json:"ComputerName" panther:"hostname" description:"The name of the host."`
	ConfigBuild     null.String `json:"ConfigBuild" description:"Config build"`
	ConfigStateHash null.String `json:"ConfigStateHash" description:"Config state hash"`
	Entitlements    null.String `json:"Entitlements" description:"Entitlements"`

	TreeID        null.String `json:"TreeId" panther:"trace_id" description:"If this event is part of a detection tree, the tree ID it is part of"`
	TreeIDDecimal null.Int64  `json:"TreeId_decimal" description:"If this event is part of a detection tree, the tree ID it is part of. (in decimal, non-hex format)"`
}

// Common context fields for events
// NOTE: All fields are not required so we can use this when parsing unknown events
// nolint:lll
type ContextEvent struct {
	BaseEvent
	ContextThreadID         null.String `json:"ContextThreadId" description:"The unique ID of a process that was spawned by another process."`
	ContextThreadIDDecimal  null.Int64  `json:"ContextThreadId_decimal" description:"The unique ID of a process that was spawned by another process (in decimal, non-hex format)."`
	ContextTimestamp        time.Time   `json:"ContextTimeStamp" tcodec:"unix" description:"The time at which an event occurred on the system, as seen by the sensor."`
	ContextTimestampDecimal time.Time   `json:"ContextTimeStamp_decimal" tcodec:"unix_ms" description:"The time at which an event occurred on the system, as seen by the sensor (in decimal, non-hex format)."`
	ContextProcessID        null.String `json:"ContextProcessId" description:"The unique ID of a process that was spawned by another process."`
	ContextProcessIDDecimal null.Int64  `json:"ContextProcessId_decimal" description:"The unique ID of a process that was spawned by another process (in decimal, non-hex format)."`
	InContext               null.String `json:"InContext" description:"In context (N/A on iOS)"`
}

var _ pantherlog.EventTimer = (*ContextEvent)(nil)

// PantherEventTime implements pantherlog.EventTimer and tries to use the device timestamp else falls back to server timestamp.
func (e *ContextEvent) PantherEventTime() time.Time {
	if e.ContextTimestamp.IsZero() {
		return e.Timestamp
	}
	return e.ContextTimestamp
}
