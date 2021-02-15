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

	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
)

// Cache pass/fail status for each policy for a few seconds so that ListResources can filter and
// sort by compliance status without having to query the compliance-api for every resource.
const complianceCacheDuration = 30 * time.Second

type complianceCacheEntry struct {
	ExpiresAt time.Time
	Resources map[string]*complianceStatus
}

type complianceStatus struct {
	SortIndex int                               // 0 is the top failing resource, 1 the next most failing, etc
	Status    compliancemodels.ComplianceStatus // PASS, FAIL, ERROR
}

var complianceCache *complianceCacheEntry

// Get the pass/fail compliance status for a particular resource.
//
// Each org's pass/fail information for all policies is cached for a minute.
func getComplianceStatus(resourceID string) (*complianceStatus, error) {
	entry, err := getOrgCompliance()
	if err != nil {
		return nil, err
	}

	if result := entry.Resources[resourceID]; result != nil {
		return result, nil
	}

	// A resource with no compliance entries is passing (no policies applied to it)
	return &complianceStatus{SortIndex: -1, Status: compliancemodels.StatusPass}, nil
}

func getOrgCompliance() (*complianceCacheEntry, error) {
	if complianceCache != nil && complianceCache.ExpiresAt.After(time.Now()) {
		return complianceCache, nil
	}

	zap.L().Debug("loading resource pass/fail from compliance-api")
	input := compliancemodels.LambdaInput{
		DescribeOrg: &compliancemodels.DescribeOrgInput{Type: "resource"},
	}
	var result compliancemodels.DescribeOrgOutput
	if _, err := complianceClient.Invoke(&input, &result); err != nil {
		zap.L().Error("failed to load resource pass/fail from compliance-api", zap.Error(err))
		return nil, err
	}

	entry := &complianceCacheEntry{
		ExpiresAt: time.Now().Add(complianceCacheDuration),
		Resources: make(map[string]*complianceStatus, len(result.Resources)),
	}
	for i, resource := range result.Resources {
		entry.Resources[resource.ID] = &complianceStatus{
			SortIndex: i,
			Status:    resource.Status,
		}
	}
	complianceCache = entry
	return entry, nil
}
