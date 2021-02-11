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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

var (
	ruleDetectionID      = "detection.rule"
	policyDetectionID    = "detection.policy"
	globalDetectionID    = "detection.global"
	dataModelDetectionID = "detection.datamodel"

	ruleDetection = &tableItem{
		ID:      ruleDetectionID,
		Enabled: true,
		Type:    models.TypeRule,
	}
	policyDetection = &tableItem{
		ID:      policyDetectionID,
		Enabled: true,
		Type:    models.TypePolicy,
	}
	globalDetection = &tableItem{
		ID:      globalDetectionID,
		Enabled: true,
		Type:    models.TypeGlobal,
	}
	dataModelDetection = &tableItem{
		ID:      dataModelDetectionID,
		Enabled: true,
		Type:    models.TypeDataModel,
	}
	allDetections = map[string]*tableItem{
		policyDetectionID:    policyDetection,
		ruleDetectionID:      ruleDetection,
		globalDetectionID:    globalDetection,
		dataModelDetectionID: dataModelDetection,
	}
)

func TestIsDetectionInMultipleEnabledPacks(t *testing.T) {
	detectionsToPacks := map[string][]*packTableItem{
		ruleDetectionID: {
			&packTableItem{Enabled: false},
		},
		globalDetectionID: {
			&packTableItem{Enabled: true},
		},
	}
	// detection not in any other pack
	result := isDetectionInEnabledPack(detectionsToPacks, policyDetectionID)
	assert.False(t, result)
	// detection in another pack, but it is disabled
	result = isDetectionInEnabledPack(detectionsToPacks, ruleDetectionID)
	assert.False(t, result)
	// detection in another pack that is enabled
	result = isDetectionInEnabledPack(detectionsToPacks, globalDetectionID)
	assert.True(t, result)
}

func TestSetupUpdatePacksVersions(t *testing.T) {
	// This tests setting up pack items when there is
	// no change needed (packs already have knowledge of all releases)
	// as well as when a new release is available, but there aren't any
	// new or removed packs
	detectionsAtVersion := allDetections
	newVersion := models.Version{ID: 2222, SemVer: "v1.2.0"}
	availableVersions := []models.Version{
		{ID: 1111, SemVer: "v1.1.0"},
		{ID: 2222, SemVer: "v1.2.0"},
	}
	packOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		PackDefinition: models.PackDefinition{
			IDs: []string{ruleDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypeRule: 1,
		}}
	packTwo := &packTableItem{
		ID:                "pack.id.2",
		AvailableVersions: availableVersions,
		PackDefinition: models.PackDefinition{
			IDs: []string{ruleDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypeRule: 1,
		}}
	packThree := &packTableItem{
		ID:                "pack.id.3",
		AvailableVersions: availableVersions,
		PackDefinition: models.PackDefinition{
			IDs: []string{ruleDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypeRule: 1,
		},
	}
	packsAtVersion := map[string]*packTableItem{
		"pack.id.1": packOne,
		"pack.id.2": packTwo,
		"pack.id.3": packThree,
	}
	// Test: no changed needed
	oldPacks := []*packTableItem{
		packOne,
		packTwo,
		packThree,
	}
	newPackItems := setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion, detectionsAtVersion)
	assert.Equal(t, 0, len(newPackItems))
	// Test: no packs added/removed, releases updated
	newVersion = models.Version{ID: 3333, SemVer: "v1.3.0"}
	newPackItems = setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion, detectionsAtVersion)
	for _, newPackItem := range newPackItems {
		assert.True(t, newPackItem.UpdateAvailable)
		assert.Equal(t, 3, len(newPackItem.AvailableVersions))
	}
}

func TestSetupPacksVersionsAddPack(t *testing.T) {
	// This tests setting up pack items when
	// a new pack is added in a release. It should be auto-disable
	// and the AvailableReleases should only include the
	// new release version
	detectionsAtVersion := allDetections
	newVersion := models.Version{ID: 3333, SemVer: "v1.3.0"}
	availableVersions := []models.Version{
		{ID: 1111, SemVer: "v1.1.0"},
		{ID: 2222, SemVer: "v1.2.0"},
	}
	// Test: New pack added
	packOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		PackDefinition: models.PackDefinition{
			IDs: []string{ruleDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypeRule: 1,
		}}
	packTwo := &packTableItem{
		ID:                "pack.id.2",
		AvailableVersions: availableVersions,
		PackDefinition: models.PackDefinition{
			IDs: []string{ruleDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypeRule: 1,
		}}
	// packThree is the "new" pack added
	packThree := &packTableItem{
		ID: "pack.id.3",
		PackDefinition: models.PackDefinition{
			IDs: []string{ruleDetectionID, policyDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypeRule:   1,
			models.TypePolicy: 1,
		},
	}
	oldPacks := []*packTableItem{
		packOne,
		packTwo, // no packThree in the oldPacks
	}
	packsAtVersion := map[string]*packTableItem{
		"pack.id.1": packOne,
		"pack.id.2": packTwo,
		"pack.id.3": packThree, // "new" packs has all three items
	}
	newPackItems := setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion, detectionsAtVersion)
	assert.Equal(t, 3, len(newPackItems)) // ensure all three items have updates
	for _, newPackItem := range newPackItems {
		// validate the newly added pack is disabled and
		// has the current field values
		if newPackItem.ID == "pack.id.3" {
			assert.False(t, newPackItem.UpdateAvailable) // while this is a new pack, the newest version has been installed (but disabled)
			assert.False(t, newPackItem.Enabled)
			assert.Equal(t, 1, len(newPackItem.AvailableVersions))
			assert.Equal(t, newVersion.ID, newPackItem.PackVersion.ID)
			assert.Equal(t, newVersion.SemVer, newPackItem.PackVersion.SemVer)
			assert.Equal(t, packThree.PackTypes, newPackItem.PackTypes) // ensure the detection types are reflected
		} else {
			assert.True(t, newPackItem.UpdateAvailable)
			// the existing packs should have 3 available versions
			assert.Equal(t, 3, len(newPackItem.AvailableVersions))
			assert.Equal(t, 1, len(newPackItem.PackTypes)) // ensure the detection types haven't changed for these packs
			assert.Equal(t, packOne.PackTypes, newPackItem.PackTypes)
		}
	}
}

func TestSetupPacksVersionsRemovePack(t *testing.T) {
	// This tests setting up the new pack items
	// when a pack is removed from a release, in which case
	// the removed pack does not get the new release in its
	// AvailableRelease
	detectionsAtVersion := allDetections
	newVersion := models.Version{ID: 3333, SemVer: "v1.3.0"}
	availableVersions := []models.Version{
		{ID: 1111, SemVer: "v1.1.0"},
		{ID: 2222, SemVer: "v1.2.0"},
	}
	// Test: pack removed
	packOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
	}
	packTwo := &packTableItem{
		ID:                "pack.id.2",
		AvailableVersions: availableVersions,
	}
	packThree := &packTableItem{
		ID:                "pack.id.3",
		AvailableVersions: availableVersions, // will be "removed" in latest release
	}
	oldPacks := []*packTableItem{
		packOne,
		packTwo,
		packThree,
	}
	packsAtVersion := map[string]*packTableItem{
		"pack.id.1": packOne,
		"pack.id.2": packTwo, // packThree "removed" from latest release
	}
	newPackItems := setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion, detectionsAtVersion)
	assert.Equal(t, 2, len(newPackItems)) // only two packs should be updated
	for _, newPackItem := range newPackItems {
		assert.True(t, newPackItem.UpdateAvailable)
		// validate the removed pack isn't returned from the function (no changes needed)
		assert.NotEqual(t, packThree.ID, newPackItem.ID)
		assert.Equal(t, 3, len(newPackItem.AvailableVersions))
	}
}

func TestSetupUpdatePackToVersion(t *testing.T) {
	// This tests setting up the updated items for
	// updating a pack to a speicific version
	// as well as testing updating to a speicfic version and enabling
	// it at the same time
	detectionsAtVersion := allDetections
	newVersion := models.Version{ID: 3333, SemVer: "v1.3.0"}
	availableVersions := []models.Version{
		{ID: 1111, SemVer: "v1.1.0"},
		{ID: 2222, SemVer: "v1.2.0"},
		newVersion,
	}
	oldPackOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		Enabled:           false,
		Description:       "original description",
		PackDefinition: models.PackDefinition{
			IDs: []string{ruleDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypeRule: 1,
		},
	}
	input := &models.PatchPackInput{
		VersionID: newVersion.ID,
		ID:        "pack.id.1",
		Enabled:   false,
	}
	packOne := oldPackOne
	// Test: success, no update to enabled status
	item := setupUpdatePackToVersion(input, newVersion, oldPackOne, packOne, detectionsAtVersion)
	assert.Equal(t, newVersion, item.PackVersion)
	assert.False(t, item.Enabled)
	// Test: success, update enabled status
	input = &models.PatchPackInput{
		VersionID: newVersion.ID,
		ID:        "pack.id.1",
		Enabled:   true,
	}
	packOne = &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		Enabled:           false,
		Description:       "new description",
	}
	item = setupUpdatePackToVersion(input, newVersion, oldPackOne, packOne, detectionsAtVersion)
	assert.Equal(t, newVersion, item.PackVersion)
	assert.True(t, item.Enabled)
	// Test: success, update detection type in pack
	input = &models.PatchPackInput{
		VersionID: newVersion.ID,
		ID:        "pack.id.1",
		Enabled:   true,
	}
	packOne = &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		Enabled:           false,
		Description:       "new description",
		PackDefinition: models.PackDefinition{
			IDs: []string{policyDetectionID},
		},
		PackTypes: map[models.DetectionType]int{
			models.TypePolicy: 1,
		},
	}
	item = setupUpdatePackToVersion(input, newVersion, oldPackOne, packOne, detectionsAtVersion)
	assert.Equal(t, newVersion, item.PackVersion)
	assert.True(t, item.Enabled)
	assert.Equal(t, packOne.PackDefinition, item.PackDefinition)
	assert.Equal(t, packOne.PackTypes, item.PackTypes)
}

func TestSetupUpdatePackToVersionOnDowngrade(t *testing.T) {
	// This tests setting up new pack table items
	// for when we need to revert / downgrade to an 'older' version
	// Test: revert to "older" version
	detectionsAtVersion := allDetections
	newVersion := models.Version{ID: 1111, SemVer: "v1.1.0"}
	availableVersions := []models.Version{
		newVersion,
		{ID: 2222, SemVer: "v1.2.0"},
	}
	input := &models.PatchPackInput{
		VersionID: newVersion.ID,
		ID:        "pack.id.1",
		Enabled:   true,
	}
	oldPackOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		Enabled:           false,
		Description:       "new description",
	}
	packOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		Enabled:           false,
		Description:       "original description",
	}
	item := setupUpdatePackToVersion(input, newVersion, oldPackOne, packOne, detectionsAtVersion)
	assert.Equal(t, newVersion, item.PackVersion)
	assert.True(t, item.Enabled)
	assert.Equal(t, 2, len(item.AvailableVersions)) // ensure even though we are downgrading, the available versions stays the same
	assert.True(t, item.UpdateAvailable)            // since we are downgrading, the update available flag should still be set
}

func TestDetectionSetLookup(t *testing.T) {
	detectionOne := &tableItem{
		ID: "id.1",
	}
	detectionTwo := &tableItem{
		ID: "id.2",
	}
	detectionThree := &tableItem{
		ID: "id.3",
	}
	// only ids that exist
	detectionsAtVersion := map[string]*tableItem{
		"id.1": detectionOne,
		"id.2": detectionTwo,
		"id.3": detectionThree,
	}
	PackDefinition := models.PackDefinition{
		IDs: []string{"id.1", "id.3"},
	}
	expectedOutput := map[string]*tableItem{
		"id.1": detectionOne,
		"id.3": detectionThree,
	}
	items := detectionSetLookup(detectionsAtVersion, PackDefinition)
	assert.Equal(t, items, expectedOutput)
	// only ids that do not exist
	PackDefinition = models.PackDefinition{
		IDs: []string{"id.4", "id.6"},
	}
	expectedOutput = map[string]*tableItem{}
	items = detectionSetLookup(detectionsAtVersion, PackDefinition)
	assert.Equal(t, items, expectedOutput)
	// mix of ids that exist and do not exist
	PackDefinition = models.PackDefinition{
		IDs: []string{"id.1", "id.6"},
	}
	expectedOutput = map[string]*tableItem{
		"id.1": detectionOne,
	}
	items = detectionSetLookup(detectionsAtVersion, PackDefinition)
	assert.Equal(t, items, expectedOutput)
}

func TestDetectionTypeSet(t *testing.T) {
	// contains single type
	detections := map[string]*tableItem{
		ruleDetectionID: allDetections[ruleDetectionID],
	}
	expectedOutput := map[models.DetectionType]int{
		models.TypeRule: 1,
	}
	types := getDetectionTypeSet(detections)
	assert.Equal(t, 1, len(types))
	assert.Equal(t, expectedOutput, types)
	// contains two types
	detections = map[string]*tableItem{
		ruleDetectionID:   allDetections[ruleDetectionID],
		policyDetectionID: allDetections[policyDetectionID],
	}
	types = getDetectionTypeSet(detections)
	assert.Equal(t, 2, len(types))
	// contains two of the same types
	detections = map[string]*tableItem{
		ruleDetectionID: allDetections[ruleDetectionID],
		"rule.id.2":     allDetections[ruleDetectionID],
	}
	expectedOutput = map[models.DetectionType]int{
		models.TypeRule: 2,
	}
	types = getDetectionTypeSet(detections)
	assert.Equal(t, expectedOutput, types)
	assert.Equal(t, 1, len(types))
	// contains four types
	types = getDetectionTypeSet(allDetections)
	assert.Equal(t, 4, len(types))
}
