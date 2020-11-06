package processor

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

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/analysis/client/operations"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

const cacheDuration = 30 * time.Second

type policyCacheEntry struct {
	LastUpdated time.Time
	Policies    policyMap
}

var policyCache policyCacheEntry

// Get enabled policies from either the memory cache or the analysis-api
func getPolicies() (policyMap, error) {
	if policyCache.Policies != nil && policyCache.LastUpdated.Add(cacheDuration).After(time.Now()) {
		// Cache entry exists and hasn't expired yet
		zap.L().Info("using policy cache",
			zap.Int("policyCount", len(policyCache.Policies)))
		return policyCache.Policies, nil
	}

	// Load from analysis-api
	result, err := analysisClient.Operations.GetEnabledPolicies(
		&operations.GetEnabledPoliciesParams{HTTPClient: httpClient, Type: string(models.AnalysisTypePOLICY)})
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load policies from analysis-api")
	}
	zap.L().Info("successfully loaded enabled policies from analysis-api",
		zap.Int("policyCount", len(result.Payload.Policies)))

	// Convert list of policies into a map by ID
	policies := make(policyMap, len(result.Payload.Policies))
	for _, policy := range result.Payload.Policies {
		policies[string(policy.ID)] = policy
	}

	policyCache = policyCacheEntry{LastUpdated: time.Now(), Policies: policies}
	return policies, nil
}
