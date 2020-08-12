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

	"go.uber.org/zap"

	alertmodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
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
	once            sync.Once
	cache           *outputsCache
	outputsAPI      = os.Getenv("OUTPUTS_API")
	refreshInterval = getRefreshInterval()
)

// getCache - Gets a pointer to the cache singleton
func getCache() *outputsCache {
	// atomic, does not allow repeating
	once.Do(func() {
		// thread safe, create a new (empty) cache
		setCache(&outputsCache{})
	})

	return cache
}

// setCache - Sets the cache
func setCache(newCache *outputsCache) {
	cache = newCache
}

// getCacheOutputs - Gets the outputs stored in the cache
func getCacheOutputs() []*outputmodels.AlertOutput {
	return getCache().Outputs
}

// setCacheOutputs - Stores the outputs in the cache
func setCacheOutputs(outputs []*outputmodels.AlertOutput) {
	getCache().Outputs = outputs
}

// getCacheExpiry - Gets the expiry time in the cache
func getCacheExpiry() time.Time {
	return getCache().Timestamp
}

// setCacheExpiry - Sets the expiry time of the cache
func setCacheExpiry(time time.Time) {
	getCache().Timestamp = time
}

// fetchOutputs - performs an API query to get a list of outputs
func fetchOutputs() ([]*outputmodels.AlertOutput, error) {
	zap.L().Debug("getting default outputs")
	input := outputmodels.LambdaInput{GetOutputsWithSecrets: &outputmodels.GetOutputsWithSecretsInput{}}
	var outputs outputmodels.GetOutputsOutput
	if err := genericapi.Invoke(lambdaClient, outputsAPI, &input, &outputs); err != nil {
		return nil, err
	}
	return outputs, nil
}

// isCacheExpired - determines if the cache has expired
func isCacheExpired() bool {
	return time.Since(getCacheExpiry()) > refreshInterval
}

// getOutputs - Gets a list of outputs from panther
func getOutputs() ([]*outputmodels.AlertOutput, error) {
	if getCache() == nil || isCacheExpired() {
		outputs, err := fetchOutputs()
		if err != nil {
			return nil, err
		}
		setCacheOutputs(outputs)
		setCacheExpiry(time.Now().UTC())
	}

	return getCacheOutputs(), nil
}

// getAlertOutputs - Get output ids for an alert
func getAlertOutputs(alert *alertmodels.Alert) ([]*outputmodels.AlertOutput, error) {
	outputIds, err := getOutputs()
	if err != nil {
		return nil, err
	}

	// If alert doesn't have outputs IDs specified, return the defaults for the severity
	if len(alert.OutputIds) == 0 {
		return getOutputsBySeverity(alert.Severity), nil
	}

	result := []*outputmodels.AlertOutput{}
	for _, output := range outputIds {
		for _, alertOutputID := range alert.OutputIds {
			if *output.OutputID == alertOutputID {
				result = append(result, output)
			}
		}
	}
	return result, nil
}

func getOutputsBySeverity(severity string) []*outputmodels.AlertOutput {
	result := []*outputmodels.AlertOutput{}
	if getCache() == nil {
		return result
	}

	for _, output := range getCacheOutputs() {
		for _, outputSeverity := range output.DefaultForSeverity {
			if severity == *outputSeverity {
				result = append(result, output)
			}
		}
	}
	return result
}
