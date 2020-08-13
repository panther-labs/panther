package delivery

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
	"os"
	"sync"
	"time"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

// getRefreshInterval - fetches the env setting or provides a default value if not set
func getRefreshInterval() time.Duration {
	intervalMins := os.Getenv("OUTPUTS_REFRESH_INTERVAL_MIN")
	if intervalMins == "" {
		intervalMins = "5"
	}
	return time.Duration(mustParseInt(intervalMins)) * time.Minute
}

// outputsCache - is a singleton holding outputs to send alerts
type outputsCache struct {
	// All cached outputs
	Outputs   []*outputmodels.AlertOutput
	Timestamp time.Time
}

// Global variables
var (
	cache           *outputsCache
	once            sync.Once
	refreshInterval = getRefreshInterval()
)

// get - Gets a pointer to the cache singleton
func (c *outputsCache) get() *outputsCache {
	// Atomic, execute only once.
	// Now, we don't have to always think about calling `cache.set(...)`
	// before using the cache.
	once.Do(func() {
		// Thread safe. create a new cache if it was nil, otherwise do nothing
		if cache == nil {
			c.set(&outputsCache{})
		}
	})
	return cache
}

// setCache - Sets the cache
func (c *outputsCache) set(newCache *outputsCache) {
	cache = newCache
}

// getOutputs - Gets the outputs stored in the cache
func (c *outputsCache) getOutputs() []*outputmodels.AlertOutput {
	return c.get().Outputs
}

// setCacheOutputs - Stores the outputs in the cache
func (c *outputsCache) setOutputs(outputs []*outputmodels.AlertOutput) {
	c.get().Outputs = outputs
}

// getExpiry - Gets the expiry time in the cache
func (c *outputsCache) getExpiry() time.Time {
	return c.get().Timestamp
}

// setExpiry - Sets the expiry time of the cache
func (c *outputsCache) setExpiry(time time.Time) {
	c.get().Timestamp = time
}

// isCacheExpired - determines if the cache has expired
func (c *outputsCache) isExpired() bool {
	return time.Since(c.getExpiry()) > refreshInterval
}
