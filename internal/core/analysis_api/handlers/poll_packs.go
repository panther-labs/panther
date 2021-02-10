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
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/hashicorp/go-version"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

func (API) PollPacks(input *models.PollPacksInput) *events.APIGatewayProxyResponse {
	var releases []models.Version
	var err error
	// determine if polling for a particular release or the latest version
	if input.VersionID != 0 {
		// first, validate the version information
		versionName, err := getReleaseName(pantherGithubConfig, input.VersionID)
		if err != nil {
			return &events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
				Body:       err.Error(),
			}
		}
		releases = []models.Version{
			{ID: input.VersionID, SemVer: versionName},
		}
	} else {
		// First, check for a new release in the github repo by listing all releases
		releases, err = listAvailableGithubReleases(pantherGithubConfig)
		if err != nil {
			// error looking up the github releases
			zap.L().Error("failed to list github releases", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
	}
	if len(releases) == 0 {
		// there aren't any releases, just return
		zap.L().Error("no releases found", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
	}
	// Second, lookup existing item values to determine if updates are available
	currentPacks, err := getPackItems(&dynamodb.ScanInput{
		TableName: &env.PackTable,
	})
	if err != nil {
		// error looking up the existing pack data
		zap.L().Error("failed to scan panther-analysis-pack table", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	// Finally, check if update is available
	latestRelease := getLatestRelease(releases)
	if isNewReleaseAvailable(latestRelease, currentPacks) {
		// If an update is available, retrieve & validate pack data and:
		// Update fields: availableReleases and updateAvailable status
		// Create any new packs: default to disabled status
		// TODO: what this doesn't handle is when there are multiple new releases that need to be registered
		err := updatePackVersions(latestRelease, currentPacks)
		if err != nil {
			// error updating pack version data
			zap.L().Error("failed to update pack releases", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
	}
	// Nothing else to do - Report success
	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func isNewReleaseAvailable(currentVersion models.Version, currentPacks []*packTableItem) bool {
	parsedCurrentVersion, err := version.NewVersion(currentVersion.SemVer)
	if err != nil {
		// Failed to parse the version string
		zap.L().Error("Failed to parse the version string for a release",
			zap.String("versionString", currentVersion.SemVer))
		return false
	}
	// if there aren't any current packs, then there is a new release available
	if len(currentPacks) == 0 {
		return true
	}
	for _, pack := range currentPacks {
		// if availableReleases doesn't contain the currentVersion, this
		// is a new release
		if !containsRelease(pack.AvailableVersions, currentVersion.ID) {
			return true
		}
		// Otherwise, check if this release is the newest value in the available releases
		for _, availablePackVersion := range pack.AvailableVersions {
			availableVersion, err := version.NewVersion(availablePackVersion.SemVer)
			if err != nil {
				continue
			}
			if parsedCurrentVersion.LessThan(availableVersion) {
				return true
			}
		}
	}
	return false
}

func containsRelease(versions []models.Version, newVersion int64) bool {
	for _, version := range versions {
		if version.ID == newVersion {
			return true
		}
	}
	return false
}

func getLatestRelease(versions []models.Version) models.Version {
	latestRelease := versions[0]
	latestReleaseVersion, err := version.NewVersion(latestRelease.SemVer)
	if err != nil {
		zap.L().Error("error parsing version string", zap.String("version", latestRelease.SemVer))
		return latestRelease
	}
	for _, release := range versions {
		version, err := version.NewVersion(release.SemVer)
		if err != nil {
			continue
		}
		if version.GreaterThan(latestReleaseVersion) {
			latestRelease = release
			latestReleaseVersion = version
		}
	}
	return latestRelease
}
