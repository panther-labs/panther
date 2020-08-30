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
	"errors"
	"time"
)

// Chain tries handlers in sequence while a NotFound error is returned.
func Chain(handlers ...Handler) Handler {
	return chainHandler(handlers)
}

type chainHandler []Handler

func (c chainHandler) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	for _, handler := range c {
		reply, err := handler.Invoke(ctx, payload)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		return reply, nil
	}
	return nil, ErrNotFound
}

func CacheProxy(maxAge time.Duration, handler Handler) Handler {
	if maxAge <= 0 {
		return handler
	}
	type cacheEntry struct {
		Output    []byte
		UpdatedAt time.Time
	}
	cache := map[string]*cacheEntry{}
	var lastInsertAt time.Time
	return HandlerFunc(func(ctx context.Context, input []byte) ([]byte, error) {
		entry, ok := cache[string(input)]
		if ok && time.Since(entry.UpdatedAt) < maxAge {
			return entry.Output, nil
		}
		output, err := handler.Invoke(ctx, input)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		// Reset the whole cache if last insert was too old to avoid memory leaks
		if time.Since(lastInsertAt) > maxAge {
			cache = map[string]*cacheEntry{}
			lastInsertAt = now
		}
		cache[string(input)] = &cacheEntry{
			Output:    output,
			UpdatedAt: now,
		}
		return output, nil
	})
}
