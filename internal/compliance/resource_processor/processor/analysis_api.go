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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
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
	listInput := analysismodels.LambdaInput{
		ListPolicies: &analysismodels.ListPoliciesInput{
			Enabled: aws.Bool(true),
			Fields: []string{
				// select only the fields we need so it fits in a single response
				"body", "id", "outputIds", "reports", "resourceTypes", "severity", "suppressions", "tags", "versionId",
			},
			PageSize: -1,
		},
	}
	var listOutput analysismodels.ListPoliciesOutput
	if _, err := analysisClient.Invoke(&listInput, &listOutput); err != nil {
		return nil, errors.WithMessage(err, "failed to load policies from analysis-api")
	}
	zap.L().Info("successfully loaded enabled policies from analysis-api",
		zap.Int("policyCount", len(listOutput.Policies)))

	// Convert list of policies into a map by ID
	policies := make(policyMap, len(listOutput.Policies))
	for _, policy := range listOutput.Policies {
		policies[policy.ID] = policy
	}

	policyCache = policyCacheEntry{LastUpdated: time.Now(), Policies: policies}
	return policies, nil
}
