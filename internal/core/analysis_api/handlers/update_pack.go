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
	"github.com/aws/aws-sdk-go/aws"
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
	// Note: currently only support `enabled` and `enabledRelease` updates from the `patch` operation
	// But you cannot update version and enabled status in same request
	if input.VersionID != 0 && input.VersionID != oldItem.PackVersion.ID {
		// we are updating the version
		return updateVersion(input, oldItem)
	}
	// we are updating the enabled status
	return updatePackEnabledStatus(input, oldItem)
}

// updatePackEnabledStatus will update the enabled status of the pack and the detections in it
func updatePackEnabledStatus(input *models.PatchPackInput, oldPackItem *packTableItem) *events.APIGatewayProxyResponse {
	if oldPackItem.Enabled == input.Enabled {
		// if the enabled status hasn't changed, just return success
		return gatewayapi.MarshalResponse(oldPackItem.Pack(), http.StatusOK)
	}
	// First, we need to update the detections enabled status
	detections, err := detectionDdbLookup(oldPackItem.PackDefinition)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Error looking up detections in pack (%s)", oldPackItem.ID),
			StatusCode: http.StatusNotFound,
		}
	}
	otherExistingPacks, err := lookupPackMembership()
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Error looking up detection pack membership (%s)", oldPackItem.ID),
			StatusCode: http.StatusNotFound,
		}
	}
	for _, detection := range detections {
		if input.Enabled || !isDetectionInEnabledPack(otherExistingPacks, input.ID, detection.ID) {
			// if we are enabling the pack, we simply need to enable all the detections in it
			// if we are disabling this pack, we need to determine if the detections
			// are in any other enabled pack
			detection.Enabled = input.Enabled
		}
	}
	// actually run the update
	for _, detection := range detections {
		_, err = writeItem(detection, input.UserID, nil)
		if err != nil {
			// TODO: should we try to rollback the other updated detections?
			return &events.APIGatewayProxyResponse{
				Body:       fmt.Sprintf("Error updating pack detections (%s)", detection.ID),
				StatusCode: http.StatusNotFound,
			}
		}
	}
	// Finally, update the pack enabled status
	oldPackItem.Enabled = input.Enabled
	err = updatePack(oldPackItem, input.UserID, aws.Bool(true))
	if err != nil {
		// TODO: should we try to rollback the other updated detections?
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Error updating pack (%s)", oldPackItem.ID),
			StatusCode: http.StatusNotFound,
		}
	}
	return gatewayapi.MarshalResponse(oldPackItem.Pack(), http.StatusOK)
}

// updatePackVersion updates the version of pack enabled in dynamo, and updates the version of the detections in the pack in dynamo
// It accomplishes this by:
// (1) downloading the relevant release/version from github,
// (2) updating the pack version in the `panther-analysis-packs` ddb
// (3) updating the detections in the pack in the `panther-analysis` ddb
func updateVersion(input *models.PatchPackInput, oldPackItem *packTableItem) *events.APIGatewayProxyResponse {
	if !oldPackItem.Enabled && input.VersionID != oldPackItem.PackVersion.ID {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot update a disabled pack (%s)", input.ID),
			StatusCode: http.StatusBadRequest,
		}
	}
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
		// ensure we keep the existing pack enabled status
		newPackItem.Enabled = oldPackItem.Enabled
		// Update the detections in the pack
		err = updateDetectionsToVersion(input.UserID, newPackItem, detectionVersionSet)
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
	newPack := setupUpdatePackToVersion(version, oldPackItem, newPackItem, newDetections)
	err = updatePack(newPack, input.UserID, aws.Bool(true))
	return newPack, err
}

// setupUpdatePackToVersion will return the new `panther-analysis-packs` ddb table item by
// updating the metadata fields to the new version values
func setupUpdatePackToVersion(version models.Version, oldPackItem *packTableItem,
	newPackItem *packTableItem, detectionVersionSet map[string]*tableItem) *packTableItem {

	// get the new detections in the pack
	newPackDetections := detectionSetLookup(detectionVersionSet, newPackItem.PackDefinition)
	packTypes := setPackTypes(newPackDetections)
	updateAvailable := isNewReleaseAvailable(version, []*packTableItem{oldPackItem})
	pack := &packTableItem{
		Enabled:           newPackItem.Enabled,
		UpdateAvailable:   updateAvailable,
		Description:       newPackItem.Description,
		PackDefinition:    newPackItem.PackDefinition,
		PackTypes:         packTypes,
		DisplayName:       newPackItem.DisplayName,
		PackVersion:       version,
		ID:                newPackItem.ID,
		AvailableVersions: oldPackItem.AvailableVersions,
	}
	return pack
}

// updatePackDetections updates detections by:
// (1) setting up new items based on release data
// (2) writing out the new items
func updateDetectionsToVersion(userID string, pack *packTableItem, newDetectionItems map[string]*tableItem) error {
	// First lookup the existing detections in this pack
	oldDetectionItems, err := detectionDdbLookup(pack.PackDefinition)
	if err != nil {
		return err
	}
	newDetections := setupUpdateDetectionsToVersion(pack, oldDetectionItems, newDetectionItems)
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
func setupUpdateDetectionsToVersion(pack *packTableItem, oldDetectionItems map[string]*tableItem,
	newDetectionItems map[string]*tableItem) []*tableItem {

	// setup slice to return
	var newItems []*tableItem
	// Then get a list of the updated detection in the pack
	newDetections := detectionSetLookup(newDetectionItems, pack.PackDefinition)
	// Loop through the new detections and update appropriate fields or
	//  create new detection
	for id, newDetection := range newDetections {
		if detection, ok := oldDetectionItems[id]; ok {
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
			// we are not updating the enabled status, simply
			// keep the existing enabled status of this detection
		} else {
			// create new detection
			newDetection.Enabled = pack.Enabled
			newItems = append(newItems, newDetection)
		}
	}
	return newItems
}

// lookupPackMembership will setup a map from detectionID -> []pack to easily track which packs
// each detection is in
func lookupPackMembership() (map[string][]*packTableItem, error) {
	// if we are disabling a pack, we need to look up detection pack memebership
	// so that if a detection spans multiple packs, we only disable it if it
	// is not enabled via another pack
	detectionToPack := make(map[string][]*packTableItem)
	scanInput, err := buildTableScanInput(env.PackTable, []models.DetectionType{models.TypePack},
		[]string{}, []expression.ConditionBuilder{}...)
	if err != nil {
		return nil, err
	}
	otherExistingPacks, err := getPackItems(scanInput)
	if err != nil {
		return nil, err
	}
	for _, pack := range otherExistingPacks {
		packDetections, err := detectionDdbLookup(pack.PackDefinition)
		if err != nil {
			return nil, err
		}
		for _, detection := range packDetections {
			detectionToPack[detection.ID] = append(detectionToPack[detection.ID], pack)
		}
	}
	return detectionToPack, nil
}

// isDetectionInMultipleEnabledPacks will return True is a detection exists in another enabled pack
// otherwise it will return False
func isDetectionInEnabledPack(detectionToPacks map[string][]*packTableItem, currentPackID string, detectionID string) bool {
	// if a user disables a pack, it disables all the detections in the pack unless those detections
	// are in another, enabled pack
	if packs, ok := detectionToPacks[detectionID]; ok {
		for _, pack := range packs {
			if pack.Enabled && pack.ID != currentPackID {
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
	// First, look up the relevant pack and detection data for this release
	// This should also validate the detections; so as not to list a release that wouldn't actually work
	// or pass validatiaons
	packVersionSet, detectionVersionSet, err := downloadValidatePackData(pantherGithubConfig, newVersion.ID)
	if err != nil {
		return err
	}
	// setup var to return slice of updated pack items
	oldPackItemsMap := make(map[string]*packTableItem)
	// convert oldPacks to a map for ease of comparison
	for _, oldPack := range oldPackItems {
		oldPackItemsMap[oldPack.ID] = oldPack
	}
	// Loop through new packs. Old/deprecated packs will simply not get updated
	for id, newPack := range packVersionSet {
		if oldPack, ok := oldPackItemsMap[id]; ok {
			// Update existing pack metadata fields: AvailableVersions and UpdateAvailable
			if !containsRelease(oldPack.AvailableVersions, newVersion.ID) {
				// only add the new version to the availableVersions if it is not already there
				oldPack.AvailableVersions = append(oldPack.AvailableVersions, newVersion)
				oldPack.UpdateAvailable = isNewReleaseAvailable(oldPack.PackVersion, []*packTableItem{oldPack})
				if err = updatePack(oldPack, oldPack.LastModifiedBy, aws.Bool(true)); err != nil {
					return err
				}
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
			newPack.UpdateAvailable = false
			newPack.PackVersion = newVersion
			newPack.LastModifiedBy = systemUserID
			newPack.CreatedBy = systemUserID
			newPack.Type = models.TypePack
			newDetections := detectionSetLookup(detectionVersionSet, newPack.PackDefinition)
			// lookup detections in this pack
			packDetectionTypes := setPackTypes(newDetections)
			newPack.PackTypes = packDetectionTypes
			if err = updatePack(newPack, newPack.LastModifiedBy, aws.Bool(false)); err != nil {
				return err
			}
			// then we should add any new detections, auto-disabled
			if err = addNewPackDetections(systemUserID, newPack, newDetections); err != nil {
				return err
			}
		}
	}
	// return no error
	return nil
}

func addNewPackDetections(userID string, newPack *packTableItem, newDetections map[string]*tableItem) error {
	// if this is a new pack, we need to determine if there are new detections
	// as well.  If so, add them but auto-disable them
	oldDetections, err := detectionDdbLookup(newPack.PackDefinition)
	if err != nil {
		return err
	}
	for _, newDetection := range newDetections {
		if _, ok := oldDetections[newDetection.ID]; !ok {
			// this is a new detection, add it and ensure it is not enabled
			newDetection.Enabled = false
			// this should only be adding new detections that don't already exist, mustExist == false
			_, err = writeItem(newDetection, userID, aws.Bool(false))
			if err != nil {
				// TODO: should we try to rollback the other updated detections?
				return err
			}
		} // else, this is an existing detection do not update it
	}
	return nil
}

// updatePack is a wrapper around the `writePack` method
func updatePack(item *packTableItem, userID string, mustExist *bool) error {
	// ensure the correct type is set
	item.Type = models.TypePack
	if err := writePack(item, userID, mustExist); err != nil {
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

// setPackTypes will loop through the detections/data models/globals that make it up
// and set the type counts. For example:
// {
//   "GLOBAL": 0, "DATAMODEL": 1, "RULE": 2, "POLICY": 3,
// }
func setPackTypes(detections map[string]*tableItem) map[models.DetectionType]int {
	packTypes := make(map[models.DetectionType]int)
	for _, detection := range detections {
		if _, ok := packTypes[detection.Type]; ok {
			packTypes[detection.Type] = packTypes[detection.Type] + 1
		} else {
			packTypes[detection.Type] = 1
		}
	}
	return packTypes
}
