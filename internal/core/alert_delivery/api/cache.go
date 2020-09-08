package api

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

	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

// alertOutputsCache - is a singleton holding outputs to send alerts
type alertOutputsCache struct {
	// All cached outputs
	Outputs         []*outputModels.AlertOutput
	Expiry          time.Time
	RefreshInterval time.Duration
}

// get - Gets a pointer to the outputsCache singleton
func (c *alertOutputsCache) get() *alertOutputsCache {
	return outputsCache
}

// set - Sets the outputsCache singleton
func (c *alertOutputsCache) set(newCache *alertOutputsCache) {
	outputsCache = newCache
}

// getOutputs - Gets the outputs stored in the cache
func (c *alertOutputsCache) getOutputs() []*outputModels.AlertOutput {
	return c.get().Outputs
}

// setOutputs - Stores the outputs in the cache
func (c *alertOutputsCache) setOutputs(outputs []*outputModels.AlertOutput) {
	c.get().Outputs = outputs
}

// getExpiry - Gets the expiry time in the cache
func (c *alertOutputsCache) getExpiry() time.Time {
	return c.get().Expiry
}

// setExpiry - Sets the expiry time of the cache
func (c *alertOutputsCache) setExpiry(time time.Time) {
	c.get().Expiry = time
}

// getRefreshInterval - Gets the expiry time in the cache
func (c *alertOutputsCache) getRefreshInterval() time.Duration {
	return c.get().RefreshInterval
}

// setRefreshInterval - Sets the expiry time of the cache
func (c *alertOutputsCache) setRefreshInterval(duration time.Duration) {
	c.get().RefreshInterval = duration
}

// isExpired - determines if the cache has expired
func (c *alertOutputsCache) isExpired() bool {
	return time.Since(c.getExpiry()) > c.getRefreshInterval()
}
