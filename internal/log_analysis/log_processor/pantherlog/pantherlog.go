package pantherlog

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// Re-export field types from the pantherlog package so event types only need to import a single package.
// This makes explaining the process of adding support for a new log type much easier.
// It also allows us to change implementations of a field type in the future without modifying parser code
type String = null.String
type Float64 = null.Float64
type Float32 = null.Float32
type Int64 = null.Int64
type Int32 = null.Int32
type Int16 = null.Int16
type Int8 = null.Int8
type Uint64 = null.Uint64
type Uint32 = null.Uint32
type Uint16 = null.Uint16
type Uint8 = null.Uint8
type Bool = null.Bool
type Time = time.Time
type RawMessage = jsoniter.RawMessage
