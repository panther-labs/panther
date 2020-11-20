package handlers

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

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
)

// Cache pass/fail status for each policy for a few seconds so that ListPolicies can filter and
// sort by compliance status without having to query the compliance-api for every policy.
const complianceCacheDuration = 3 * time.Second

type complianceCacheEntry struct {
	ExpiresAt time.Time
	Policies  map[string]*complianceStatus
}

type complianceStatus struct {
	SortIndex int                               // 0 is the top failing resource, 1 the next most failing, etc
	Status    compliancemodels.ComplianceStatus // PASS, FAIL, ERROR, UNKNOWN
}

// Compliance-api queries are not very efficient right now.
// We cache the results here for a short period of time to minimize time the end-user is blocked
// when loading the policy detail page.
var complianceCache *complianceCacheEntry

// Get the pass/fail compliance status for a particular policy.
//
// Each org's pass/fail information for all policies is cached for a very short time.
func getComplianceStatus(policyID string) (*complianceStatus, error) {
	entry, err := getOrgCompliance()
	if err != nil {
		return nil, err
	}

	if result := entry.Policies[policyID]; result != nil {
		return result, nil
	}

	// A policy with no compliance entries is passing (it didn't evaluate anything)
	return &complianceStatus{SortIndex: -1, Status: compliancemodels.StatusPass}, nil
}

func getOrgCompliance() (*complianceCacheEntry, error) {
	if complianceCache != nil && complianceCache.ExpiresAt.After(time.Now()) {
		return complianceCache, nil
	}

	zap.L().Debug("loading policy pass/fail from compliance-api")
	input := compliancemodels.LambdaInput{
		DescribeOrg: &compliancemodels.DescribeOrgInput{Type: "policy"},
	}
	var result compliancemodels.DescribeOrgOutput
	if _, err := complianceClient.Invoke(&input, &result); err != nil {
		zap.L().Error("failed to load policy pass/fail from compliance-api", zap.Error(err))
		return nil, err
	}

	entry := &complianceCacheEntry{
		ExpiresAt: time.Now().Add(complianceCacheDuration),
		Policies:  make(map[string]*complianceStatus, len(result.Policies)),
	}
	for i, policy := range result.Policies {
		entry.Policies[policy.ID] = &complianceStatus{
			SortIndex: i,
			Status:    policy.Status,
		}
	}
	complianceCache = entry
	return entry, nil
}

// Delete compliance status for entire policies or just some resource types within each policy.
func complianceBatchDelete(policies []models.DeleteEntry, resourceTypes []string) error {
	entries := make([]compliancemodels.DeleteStatusEntry, len(policies))
	for i, policy := range policies {
		entries[i] = compliancemodels.DeleteStatusEntry{
			Policy: &compliancemodels.DeletePolicy{
				ID:            policy.ID,
				ResourceTypes: resourceTypes,
			},
		}
	}

	zap.L().Info("deleting compliance entries", zap.Int("itemCount", len(entries)))
	input := compliancemodels.LambdaInput{
		DeleteStatus: &compliancemodels.DeleteStatusInput{Entries: entries},
	}
	if _, err := complianceClient.Invoke(&input, nil); err != nil {
		zap.L().Error("failed to delete compliance status", zap.Error(err))
		return err
	}

	// Remove the cached status as well
	if complianceCache != nil {
		for _, policy := range policies {
			delete(complianceCache.Policies, policy.ID)
		}
	}

	return nil
}

// Some policy changes trigger immediate or near-immediate changes to the compliance status.
//
// Examples:
//    - disabled policy => delete all associated compliance status
//    - changed python body => queue policy for full re-analysis
func updateComplianceStatus(oldItem, newItem *tableItem) error {
	if !newItem.Enabled {
		if oldItem != nil && oldItem.Enabled {
			zap.L().Info("policy is now disabled - deleting compliance status",
				zap.String("policyId", newItem.ID))
			return complianceBatchDelete(
				[]models.DeleteEntry{{ID: newItem.ID}}, []string{})
		}

		zap.L().Debug("policy remains disabled - no compliance updates required")
		return nil
	}

	// Delete compliance status for resource types which no longer apply
	if oldItem != nil && len(newItem.ResourceTypes) > 0 {
		if deletedTypes := setDifference(oldItem.ResourceTypes, newItem.ResourceTypes); len(deletedTypes) > 0 {
			zap.L().Info("policy no longer applies to some resource types - deleting compliance status",
				zap.String("policyId", newItem.ID),
				zap.Strings("deletedTypes", deletedTypes))
			entries := []models.DeleteEntry{{ID: newItem.ID}}
			if err := complianceBatchDelete(entries, deletedTypes); err != nil {
				return err
			}
		}
	}

	// Some changes require re-evaluating the entire policy
	if oldItem == nil || !oldItem.Enabled || oldItem.Body != newItem.Body || // newly enabled or updated Python
		(len(oldItem.ResourceTypes) > 0 && len(newItem.ResourceTypes) == 0) || // all resource types
		len(setDifference(newItem.ResourceTypes, oldItem.ResourceTypes)) > 0 { // additional resource types

		return queuePolicy(newItem)
	}

	// At this point, we know the compliance value (PASS/FAIL) won't change for any (policy, resource) pairs.
	// In other words, we don't need to re-evaluate the policy with the Python engine.
	//
	// But the compliance table has columns for severity and suppression -
	// if either of those changed, we can update the compliance API directly.
	if oldItem.Severity != newItem.Severity || !setEquality(oldItem.Suppressions, newItem.Suppressions) {
		return updateComplianceMetadata(newItem)
	}

	zap.L().Debug("policy has no major changes - no compliance updates required")
	return nil
}

// Update compliance status entries directly.
//
// This is used when only the policy severity / suppressions change - we don't need to rescan
// all affected resources in this case.
func updateComplianceMetadata(policy *tableItem) error {
	zap.L().Info("updating compliance status entry",
		zap.String("policyId", policy.ID),
	)

	input := compliancemodels.LambdaInput{
		UpdateMetadata: &compliancemodels.UpdateMetadataInput{
			PolicyID:     policy.ID,
			Severity:     policy.Severity,
			Suppressions: policy.Suppressions,
		},
	}

	_, err := complianceClient.Invoke(&input, nil)
	return err
}
