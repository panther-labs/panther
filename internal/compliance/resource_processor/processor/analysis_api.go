package processor

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
		zap.L().Error("failed to load policies from analysis-api", zap.Error(err))
		return nil, err
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

func getGlobalPolicy() (*models.EnabledPolicy, error) {
	if policyCache.Policies != nil && policyCache.LastUpdated.Add(cacheDuration).After(time.Now()) {
		// Cache entry exists and hasn't expired yet
		if globalPolicy, ok := policyCache.Policies[globalPolicy]; ok {
			return globalPolicy, nil
		}
	}

	globalPolicy, err := analysisClient.Operations.GetPolicy(
		&operations.GetPolicyParams{
			PolicyID:   globalPolicy,
			VersionID:  nil,
			HTTPClient: httpClient,
		})
	if err != nil {
		return nil, err
	}

	// This should be easily extendable to multiple global policies by getting all policies and returning a list here
	return &models.EnabledPolicy{
		Body:          globalPolicy.Payload.Body,
		ID:            globalPolicy.Payload.ID,
		ResourceTypes: globalPolicy.Payload.ResourceTypes,
		Severity:      globalPolicy.Payload.Severity,
		Suppressions:  globalPolicy.Payload.Suppressions,
		VersionID:     globalPolicy.Payload.VersionID,
	}, nil
}
