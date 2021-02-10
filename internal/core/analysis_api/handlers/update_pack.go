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
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) PatchPack(input *models.PatchPackInput) *events.APIGatewayProxyResponse {
	// This is a partial update, so lookup existing item values
	oldItem, err := dynamoGetPack(input.ID, true)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error finding %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if oldItem == nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot find %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusNotFound,
		}
	}
	if !input.Enabled && input.VersionID != oldItem.PackVersion.ID {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot update a disabled pack (%s)", input.ID),
			StatusCode: http.StatusBadRequest,
		}
	}
	// Update the enabled status and enabledRelease if it has changed
	// Note: currently only support `enabled` and `enabledRelease` updates from the `patch` operation
	return updatePackVersion(input, oldItem)
}

// updatePackVersion updates the version of pack enabled in dynamo, and updates the version of the detections in the pack in dynamo
// It accomplishes this by:
// (1) downloading the relevant release/version from github,
// (2) updating the pack version in the `panther-analysis-packs` ddb
// (3) updating the detections in the pack in the `panther-analysis` ddb
func updatePackVersion(input *models.PatchPackInput, oldPackItem *packTableItem) *events.APIGatewayProxyResponse {
	// First, look up the relevant pack and detection data for this release
	packVersionSet, detectionVersionSet, err := downloadValidatePackData(pantherGithubConfig, input.VersionID)
	if err != nil {
		zap.L().Error("error downloading and validating pack data", zap.Error(err))
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error downloading pack version (%d)", input.VersionID),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if newPackItem, ok := packVersionSet[input.ID]; ok {
		// Update the detections in the pack
		err = updateDetectionsToVersion(input.UserID, oldPackItem, newPackItem, detectionVersionSet)
		if err != nil {
			zap.L().Error("Error updating pack detections", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		// Then, update the pack metadata and detection types
		newPack, err := updatePackToVersion(input, oldPackItem, newPackItem, detectionVersionSet)
		if err != nil {
			// TODO: do we need to attempt to rollback the update if the pack detection update fails?
			zap.L().Error("Error updating pack metadata", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		// return success
		return gatewayapi.MarshalResponse(newPack.Pack(), http.StatusOK)
	}
	zap.L().Error("Trying to update pack to a version where it does not exist",
		zap.String("pack", input.ID),
		zap.Int64("version", input.VersionID))
	return &events.APIGatewayProxyResponse{
		Body:       fmt.Sprintf("Internal error updating pack version (%d)", input.VersionID),
		StatusCode: http.StatusInternalServerError,
	}
}

// updatePackToVersion will update a pack to a specific version by:
// (1) ensuring the new version is in the pack's list of available versions
// (2) setting up the new `panther-anlaysis-packs` table item
// (3) calling the update using the new table item
func updatePackToVersion(input *models.PatchPackInput, oldPackItem *packTableItem,
	newPackItem *packTableItem, newDetections map[string]*tableItem) (*packTableItem, error) {

	// check that the new version is in the list of available versions
	if !containsRelease(oldPackItem.AvailableVersions, input.VersionID) {
		return nil, fmt.Errorf("attempting to enable a version (%d) that does not exist for pack (%s)", input.VersionID, oldPackItem.ID)
	}
	versionName, err := getReleaseName(pantherGithubConfig, input.VersionID)
	if err != nil {
		return nil, err
	}
	version := models.Version{
		ID:     input.VersionID,
		SemVer: versionName,
	}
	newPack := setupUpdatePackToVersion(input, version, oldPackItem, newPackItem, newDetections)
	err = updatePack(newPack, input.UserID)
	return newPack, err
}

// setupUpdatePackToVersion will return the new `panther-analysis-packs` ddb table item by
// updating the metadata fields to the new version values
func setupUpdatePackToVersion(input *models.PatchPackInput, version models.Version, oldPackItem *packTableItem,
	newPackItem *packTableItem, detectionVersionSet map[string]*tableItem) *packTableItem {

	// get the new detections in the pack
	newPackDetections := detectionSetLookup(detectionVersionSet, newPackItem.PackDefinition)
	packDetectionTypes := getDetectionTypeSet(newPackDetections)
	updateAvailable := isNewReleaseAvailable(version, []*packTableItem{oldPackItem})
	pack := &packTableItem{
		Enabled:           input.Enabled, // update the item enablement status if it has been updated
		UpdateAvailable:   updateAvailable,
		Description:       newPackItem.Description,
		PackDefinition:    newPackItem.PackDefinition,
		PackTypes:         packDetectionTypes,
		DisplayName:       newPackItem.DisplayName,
		PackVersion:       version,
		ID:                input.ID,
		AvailableVersions: oldPackItem.AvailableVersions,
	}
	return pack
}

// updatePackDetections updates detections by:
// (1) setting up new items based on release data
// (2) writing out the new items
func updateDetectionsToVersion(userID string, oldPack *packTableItem, pack *packTableItem, newDetectionItems map[string]*tableItem) error {
	newDetections, err := setupUpdateDetectionsToVersion(oldPack, pack, newDetectionItems)
	if err != nil {
		return err
	}
	for _, newDetection := range newDetections {
		_, err = writeItem(newDetection, userID, nil)
		if err != nil {
			// TODO: should we try to rollback the other updated detections?
			return err
		}
	}
	return nil
}

// setupUpdatePackDetections is a helper method that will generate the new `panther-analysis` ddb table items
func setupUpdateDetectionsToVersion(oldPack *packTableItem, pack *packTableItem, newDetectionItems map[string]*tableItem) ([]*tableItem, error) {
	// setup slice to return
	var newItems []*tableItem
	// First lookup the existing detections in this pack
	detections, err := detectionDdbLookup(pack.PackDefinition)
	if err != nil {
		return nil, err
	}
	// Then get a list of the updated detection in the pack
	newDetections := detectionSetLookup(newDetectionItems, pack.PackDefinition)
	if err != nil {
		return nil, err
	}
	// if we are enabling or disabling the pack, we need to enable/disable
	// the detections in it.
	// if this is simply updating the pack to a new version, we should
	// not update the enabled status of the detections in it
	// This will ensure user-enabled / user-disabled detections will remain
	enabledStatusChanged := false
	var otherExistingPacks []*packTableItem
	if oldPack.Enabled != pack.Enabled {
		enabledStatusChanged = true
		// if we are disabling a pack, we need to look up detection pack memebership
		// so that if a detection spans multiple packs, we only disable it if it
		// is not enabled via another pack
		// look up all other packs not including this one
		filter := expression.NotEqual(expression.Name("lowerId"), expression.Value(strings.ToLower(pack.ID)))
		scanInput, err := buildTableScanInput(env.PackTable, []models.DetectionType{models.TypePack},
			[]string{}, []expression.ConditionBuilder{filter}...)
		if err != nil {
			return nil, err
		}
		otherExistingPacks, err = getPackItems(scanInput)
		if err != nil {
			return nil, err
		}
	}
	// Loop through the new detections and update appropriate fields or
	//  create new detection
	for id, newDetection := range newDetections {
		if detection, ok := detections[id]; ok {
			// update existing detection
			detection.Body = newDetection.Body
			// detection.DedupPeriodMinutes = newDetection.DedupPeriodMinutes
			detection.Description = newDetection.Description
			detection.DisplayName = newDetection.DisplayName
			detection.ResourceTypes = newDetection.ResourceTypes // aka LogTypes
			// detection.OutputIDs = newDetection.OutputIDs
			detection.Reference = newDetection.Reference
			detection.Reports = newDetection.Reports
			detection.Runbook = newDetection.Runbook
			// detection.Severity = newDetection.Severity
			detection.Tags = newDetection.Tags
			detection.Tests = newDetection.Tests
			// detection.Threshold = newDetection.Threshold
			newItems = append(newItems, detection)
			if enabledStatusChanged {
				// if we are disabling this pack, make sure
				// the detections in it aren't in another enabled
				// pack before disabling it
				if !pack.Enabled {
					detection.Enabled = isDetectionInMultipleEnabledPacks(otherExistingPacks, id)
				}
				detection.Enabled = pack.Enabled
			}
		} else {
			// create new detection
			newItems = append(newItems, newDetection)
		}
	}
	return newItems, nil
}

// isDetectionInMultipleEnabledPacks will return True is a detection exists in another enabled pack
// otherwise it will return False
func isDetectionInMultipleEnabledPacks(packs []*packTableItem, detectionID string) bool {
	// if a user disables a pack, it disables all the detections in the pack unless those detections are in another pack
	for _, pack := range packs {
		packDetections, err := detectionDdbLookup(pack.PackDefinition)
		if err != nil {
			zap.L().Error("error looking up detections in pack", zap.String("packId", pack.ID))
			return false
		}
		if _, ok := packDetections[detectionID]; ok {
			// This detection is in another pack:
			// If that other pack is enabled, go ahead and return true;
			// otherwise, continuing checking for any enabled pack that
			// contains this detection
			if pack.Enabled {
				return true
			}
		}
	}
	// if this detection does not exist in any other pack OR
	// all packs that this detection is in are disabled, return false
	return false
}

// updatePackVersions update the `AvailableVersions` and `UpdateAvailable` metadata fields in the
// `panther-analysis-packs` ddb table
func updatePackVersions(newVersion models.Version, oldPackItems []*packTableItem) error {
	// First, look up the relevate pack and detection data for this release
	// This should also validate the detections; so as not to list a release that wouldn't actually work
	// or pass validatiaons
	packVersionSet, detectionVersionSet, err := downloadValidatePackData(pantherGithubConfig, newVersion.ID)
	if err != nil {
		return err
	}
	newPacks := setupUpdatePacksVersions(newVersion, oldPackItems, packVersionSet, detectionVersionSet)
	if err != nil {
		return err
	}
	for _, newPack := range newPacks {
		if err = updatePack(newPack, newPack.LastModifiedBy); err != nil {
			return err
		}
	}
	return nil
}

// setupUpdatePacksVersions will create the new table items to write to the `panther-analysis-packs` ddb table
// it ensures a new version is added to `AvailableVersions` and the `UpdateAvailable` is set appropriately
func setupUpdatePacksVersions(newVersion models.Version, oldPackItems []*packTableItem,
	newPackItems map[string]*packTableItem, newPackDetections map[string]*tableItem) []*packTableItem {

	// setup var to return slice of updated pack items
	var newPacks []*packTableItem
	oldPackItemsMap := make(map[string]*packTableItem)
	// convert oldPacks to a map for ease of comparison
	for _, oldPack := range oldPackItems {
		oldPackItemsMap[oldPack.ID] = oldPack
	}
	// Loop through new packs. Old/deprecated packs will simply not get updated
	for id, newPack := range newPackItems {
		if oldPack, ok := oldPackItemsMap[id]; ok {
			// Update existing pack metadata fields: AvailableVersions and UpdateAvailable
			if !containsRelease(oldPack.AvailableVersions, newVersion.ID) {
				// only add the new version to the availableVersions if it is not already there
				oldPack.AvailableVersions = append(oldPack.AvailableVersions, newVersion)
				oldPack.UpdateAvailable = true
				newPacks = append(newPacks, oldPack)
			} else {
				// the pack already knows about this version, just continue
				continue
			}
		} else {
			// Add a new pack, and auto-disable it. AvailableVersionss will only
			// contain the version where it was added
			newPack.Enabled = false
			newPack.AvailableVersions = []models.Version{newVersion}
			// this is a new pack, adding the only version applicable to it so no update is available
			// lookup detections that will be in this pack
			packDetectionTypes := getDetectionTypeSet(detectionSetLookup(newPackDetections, newPack.PackDefinition))
			newPack.PackTypes = packDetectionTypes
			newPack.UpdateAvailable = false
			newPack.PackVersion = newVersion
			newPack.LastModifiedBy = systemUserID
			newPack.CreatedBy = systemUserID
			newPack.Type = models.TypePack
			newPacks = append(newPacks, newPack)
		}
	}
	return newPacks
}

// updatePack is a wrapper around the `writePack` method
func updatePack(item *packTableItem, userID string) error {
	// ensure the correct type is set
	item.Type = models.TypePack
	if err := writePack(item, userID, nil); err != nil {
		return err
	}
	return nil
}

func detectionDdbLookup(detectionPattern models.PackDefinition) (map[string]*tableItem, error) {
	items := make(map[string]*tableItem)

	var filters []expression.ConditionBuilder

	// Currently only support specifying IDs
	if len(detectionPattern.IDs) > 0 {
		idFilter := expression.AttributeNotExists(expression.Name("lowerId"))
		for _, id := range detectionPattern.IDs {
			idFilter = idFilter.Or(expression.Contains(expression.Name("lowerId"), strings.ToLower(id)))
		}
		filters = append(filters, idFilter)
	}

	// Build the scan input
	// include all detection types
	scanInput, err := buildScanInput(
		[]models.DetectionType{},
		[]string{},
		filters...)
	if err != nil {
		return nil, err
	}

	// scan for all detections
	err = scanPages(scanInput, func(item tableItem) error {
		items[item.ID] = &item
		return nil
	})
	if err != nil {
		return nil, err
	}

	return items, nil
}

func detectionSetLookup(newDetections map[string]*tableItem, input models.PackDefinition) map[string]*tableItem {
	items := make(map[string]*tableItem)
	// Currently only support specifying IDs
	if len(input.IDs) > 0 {
		for _, id := range input.IDs {
			if detection, ok := newDetections[id]; ok {
				items[detection.ID] = detection
			} else {
				zap.L().Error("pack definition includes a detection that does not exist",
					zap.String("detectionId", id))
			}
		}
	}

	return items
}

func getDetectionTypeSet(detections map[string]*tableItem) map[models.DetectionType]int {
	detectionTypes := make(map[models.DetectionType]int)
	for _, detection := range detections {
		if _, ok := detectionTypes[detection.Type]; ok {
			detectionTypes[detection.Type] = detectionTypes[detection.Type] + 1
		} else {
			detectionTypes[detection.Type] = 1
		}
	}
	return detectionTypes
}
