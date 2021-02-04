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
	"reflect"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

var (
	// This index is filled by mustBuild
	knownEventNames = map[string]bool{}
	// TypeUnknownEvent is a special event collects all crowdstrike events that don't yet have a registered log type
	TypeUnknownEvent = logtypes.MustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".Unknown",
		Description:  `This event is used to store all unknown crowdstrike log events`,
		ReferenceURL: `-`,
		NewEvent:     func() interface{} { return &UnknownEventWithPayload{} },
	})
)

// This event is a catch-all event for all (yet) unknown crowdstrike events
type UnknownEventWithPayload struct {
	// We neethe ed the embedding to parse the base fields of the payload
	UnknownEvent
	UnknownPayload *jsoniter.RawMessage `json:"unknown_payload" validate:"required" description:"The full JSON payload of the event"`
}

// This event holds all common fields for crowdstrike events.
type UnknownEvent struct {
	EventSimpleName null.String `json:"event_simpleName" validate:"required" description:"Event name"`
	ContextEvent
}

// Register jsoniter decoder for UnknownEventWithPayload
func init() {
	typUnknown := reflect.TypeOf(UnknownEventWithPayload{})
	jsoniter.RegisterTypeDecoderFunc(typUnknown.String(), decodeUnknownEventWithPayload)
}

// The decoder keeps the raw JSON event to use as a payload and parses to the embedded UnknownEvent.
// It fails if the `event_simpleName` is empty or one of the known event names.
// We validate this during decoding so we can use the logtypes.MustRegisterJSON helper and to not
// waste cycles on reflect-based validation during classification.
func decodeUnknownEventWithPayload(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	event := (*UnknownEventWithPayload)(ptr)
	// Peek the whole JSON
	peek := iter.SkipAndReturnBytes()
	iter2 := iter.Pool().BorrowIterator(peek)
	iter2.ReadVal(&event.UnknownEvent)
	err := iter2.Error
	iter2.Pool().ReturnIterator(iter2)
	if err != nil {
		// Copy over the error
		iter.ReportError(`ReadCrowdstrikeUnknownEvent`, err.Error())
		return
	}

	// We validate here so that we don't copy the payload in vain
	if name := event.EventSimpleName.Value; name == "" {
		iter.ReportError(`ReadCrowdstrikeUnknownEvent`, `empty event simple name`)
		return
	} else if knownEventNames[name] {
		iter.ReportError(`ReadCrowdstrikeUnknownEvent`, `known crowdstrike event`)
		return
	}

	// We need to copy the raw message as next call to ReadVal will reuse the buffer
	payload := make([]byte, len(peek))
	copy(payload, peek)
	event.UnknownPayload = (*jsoniter.RawMessage)(&payload)
}
