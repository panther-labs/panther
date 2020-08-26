package lambdamux

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
	"context"
	"encoding/json"
)

// Handler is a Lambda handler that intercepts the raw JSON payload
type Handler interface {
	HandleRaw(ctx context.Context, msg json.RawMessage) (json.RawMessage, error)
}

// HandlerFunc is a function implementing Handler
type HandlerFunc func(ctx context.Context, msg json.RawMessage) (json.RawMessage, error)

// HandleRaw implements Handler
func (f HandlerFunc) HandleRaw(ctx context.Context, msg json.RawMessage) (json.RawMessage, error) {
	return f(ctx, msg)
}
