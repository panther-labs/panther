package cache

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
	"time"

	"go.uber.org/zap"
)

// A cache that will be refreshed
type Refreshable struct {
	kv              map[string]interface{}
	refreshFunc     func() (map[string]interface{}, error)
	minimumInterval time.Duration
	lastRefresh     time.Time
}

func New(refreshFunc func() (map[string]interface{}, error)) *Refreshable {
	return &Refreshable{
		kv:              make(map[string]interface{}),
		refreshFunc:     refreshFunc,
		minimumInterval: 1 * time.Minute,
	}
}

// Retrieves the value for the provided key from the cache. It will return an empty string if no value was present.
// If the key is not present in the cache and more than `lastRefresh` time has passed since the last time
// the cache was refreshed, we try to refresh the cache again.
func (c *Refreshable) Get(key string) (value interface{}, found bool) {
	value, found = c.kv[key]
	// Invoke refresh function if the value was not found
	// Avoid invoking the refresh function multiple times
	if !found && time.Since(c.lastRefresh) > c.minimumInterval {
		c.runRefresh()
		value, found = c.kv[key]
	}
	return value, found
}

// Runs the fresh method and repopulate the cache
func (c *Refreshable) runRefresh() {
	newMap, err := c.refreshFunc()
	if err != nil {
		zap.L().Warn("failed to refresh cache", zap.Error(err))
		return
	}
	c.kv = newMap
	c.lastRefresh = time.Now()
}
