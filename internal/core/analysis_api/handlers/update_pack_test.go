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

func TestSetupUpdatePacksVersions(t *testing.T) {
	// This tests setting up pack items when there is
	// no change needed (packs already have knowledge of all releases)
	// as well as when a new release is available, but there aren't any
	// new or removed packs
	newVersion := models.Version{ID: 2222, Name: "v1.2.0"}
	availableVersions := []models.Version{
		{ID: 1111, Name: "v1.1.0"},
		{ID: 2222, Name: "v1.2.0"},
	}
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
		AvailableVersions: availableVersions,
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
	newPackItems := setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion)
	assert.Equal(t, 0, len(newPackItems))
	// Test: no packs added/removed, releases updated
	newVersion = models.Version{ID: 3333, Name: "v1.3.0"}
	newPackItems = setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion)
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
	newVersion := models.Version{ID: 3333, Name: "v1.3.0"}
	availableVersions := []models.Version{
		{ID: 1111, Name: "v1.1.0"},
		{ID: 2222, Name: "v1.2.0"},
	}
	// Test: New pack added
	packOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
	}
	packTwo := &packTableItem{
		ID:                "pack.id.2",
		AvailableVersions: availableVersions,
	}
	packThree := &packTableItem{
		ID: "pack.id.3", // removed available versions from "new" pack
	}
	oldPacks := []*packTableItem{
		packOne,
		packTwo, // removed packThree from oldPacks
	}
	packsAtVersion := map[string]*packTableItem{
		"pack.id.1": packOne,
		"pack.id.2": packTwo,
		"pack.id.3": packThree, // pack cache of "new" packs has all three items
	}
	newPackItems := setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion)
	assert.Equal(t, 3, len(newPackItems)) // ensure all three items have updates
	for _, newPackItem := range newPackItems {
		assert.True(t, newPackItem.UpdateAvailable)
		// validate the newly added pack is disabled and
		// has the current field values
		if newPackItem.ID == "pack.id.3" {
			assert.False(t, newPackItem.Enabled)
			assert.Equal(t, 1, len(newPackItem.AvailableVersions))
			assert.Equal(t, newVersion.ID, newPackItem.PackVersion.ID)
			assert.Equal(t, newVersion.Name, newPackItem.PackVersion.Name)
		} else {
			// the existing packs should have 3 available versions
			assert.Equal(t, 3, len(newPackItem.AvailableVersions))
		}
	}
}

func TestSetupPacksVersionsRemovePack(t *testing.T) {
	// This tests setting up the new pack items
	// when a pack is removed from a release, in which case
	// the removed pack does not get the new release in its
	// AvailableRelease
	newVersion := models.Version{ID: 3333, Name: "v1.3.0"}
	availableVersions := []models.Version{
		{ID: 1111, Name: "v1.1.0"},
		{ID: 2222, Name: "v1.2.0"},
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
	newPackItems := setupUpdatePacksVersions(newVersion, oldPacks, packsAtVersion)
	assert.Equal(t, 2, len(newPackItems)) // only two packs should be updated
	for _, newPackItem := range newPackItems {
		assert.True(t, newPackItem.UpdateAvailable)
		// validate the removed pack isn't returned from the function (no changes needed)
		assert.NotEqual(t, packThree.ID, newPackItem.ID)
		assert.Equal(t, 3, len(newPackItem.AvailableVersions))
	}
}

func TestSetupUpdateToVersion(t *testing.T) {
	// This tests setting up the updated items for
	// updating a pack to a speicific version
	// as well as testing updating to a speicfic version and enabling
	// it at the same time
	newVersion := models.Version{ID: 3333, Name: "v1.3.0"}
	availableVersions := []models.Version{
		{ID: 1111, Name: "v1.1.0"},
		{ID: 2222, Name: "v1.2.0"},
		newVersion,
	}
	oldPackOne := &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		Enabled:           false,
		Description:       "original description",
	}
	input := &models.PatchPackInput{
		PackVersion: newVersion,
		ID:          "pack.id.1",
		Enabled:     false,
	}
	packOne := oldPackOne
	// Test: success, no update to enabled status
	item := setupUpdatePackToVersion(input, oldPackOne, packOne)
	assert.Equal(t, newVersion, item.PackVersion)
	assert.False(t, item.Enabled)
	// Test: success, update enabled status
	input = &models.PatchPackInput{
		PackVersion: newVersion,
		ID:          "pack.id.1",
		Enabled:     true,
	}
	packOne = &packTableItem{
		ID:                "pack.id.1",
		AvailableVersions: availableVersions,
		Enabled:           false,
		Description:       "new description",
	}
	item = setupUpdatePackToVersion(input, oldPackOne, packOne)
	assert.Equal(t, newVersion, item.PackVersion)
	assert.True(t, item.Enabled)

	// TODO: Test: update a pack that doesn't exist in this version
}
func TestSetupUpdateToVersionOnDowngrade(t *testing.T) {
	// This tests setting up new pack table items
	// for when we need to revert / downgrade to an 'older' version
	// Test: revert to "older" version
	newVersion := models.Version{ID: 1111, Name: "v1.1.0"}
	availableVersions := []models.Version{
		newVersion,
		{ID: 2222, Name: "v1.2.0"},
	}
	input := &models.PatchPackInput{
		PackVersion: newVersion,
		ID:          "pack.id.1",
		Enabled:     true,
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
	item := setupUpdatePackToVersion(input, oldPackOne, packOne)
	assert.Equal(t, newVersion, item.PackVersion)
	assert.True(t, item.Enabled)
	assert.Equal(t, 2, len(item.AvailableVersions)) // ensure even though we are downgrading, the available versions stays the same
	assert.True(t, item.UpdateAvailable)            // since we are downgrading, the update available flag should still be set
}

func TestDetectionCacheLookup(t *testing.T) {
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
	detectionPattern := models.DetectionPattern{
		IDs: []string{"id.1", "id.3"},
	}
	expectedOutput := map[string]*tableItem{
		"id.1": detectionOne,
		"id.3": detectionThree,
	}
	items := detectionSetLookup(detectionsAtVersion, detectionPattern)
	assert.Equal(t, items, expectedOutput)
	// only ids that do not exist
	detectionPattern = models.DetectionPattern{
		IDs: []string{"id.4", "id.6"},
	}
	expectedOutput = map[string]*tableItem{}
	items = detectionSetLookup(detectionsAtVersion, detectionPattern)
	assert.Equal(t, items, expectedOutput)
	// mix of ids that exist and do not exist
	detectionPattern = models.DetectionPattern{
		IDs: []string{"id.1", "id.6"},
	}
	expectedOutput = map[string]*tableItem{
		"id.1": detectionOne,
	}
	items = detectionSetLookup(detectionsAtVersion, detectionPattern)
	assert.Equal(t, items, expectedOutput)
}
