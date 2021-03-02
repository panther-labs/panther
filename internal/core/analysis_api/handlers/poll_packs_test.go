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

func TestIsNewReleaseAvailable(t *testing.T) {
	newVersion := models.Version{
		ID: 2222, SemVer: "v1.2.0",
	}
	enabledVersion := models.Version{
		SemVer: "v0.1.0",
	}
	currentPacks := []*packTableItem{
		{
			PackVersion: enabledVersion,
			AvailableVersions: []models.Version{
				enabledVersion,
			},
		},
	}
	// Test new release is available
	result := isNewReleaseAvailable(newVersion, currentPacks)
	assert.True(t, result)
	// Test at current release
	enabledVersion = models.Version{
		SemVer: "v1.2.0",
	}
	currentPacks = []*packTableItem{
		{
			PackVersion: enabledVersion,
			AvailableVersions: []models.Version{
				enabledVersion,
				newVersion,
			},
		},
	}
	result = isNewReleaseAvailable(enabledVersion, currentPacks)
	assert.False(t, result)
	// Test malformed version string
	enabledVersion = models.Version{
		SemVer: "-a.1.0",
	}
	currentPacks = []*packTableItem{
		{
			PackVersion: enabledVersion,
			AvailableVersions: []models.Version{
				enabledVersion,
				newVersion,
			},
		},
	}
	result = isNewReleaseAvailable(enabledVersion, currentPacks)
	assert.False(t, result)
	// Test no current packs, new release is available
	currentPacks = []*packTableItem{}
	result = isNewReleaseAvailable(newVersion, currentPacks)
	assert.True(t, result)
}

func TestContainsRelease(t *testing.T) {
	releases := []models.Version{
		{ID: 1111, SemVer: "v1.1.0"},
		{ID: 2222, SemVer: "v1.2.0"},
	}
	contains := models.Version{
		ID:     1111,
		SemVer: "v1.1.0",
	}
	result := containsRelease(releases, contains.ID)
	assert.True(t, result)
	doesNotContain := models.Version{
		ID:     3333,
		SemVer: "v1.3.0",
	}
	result = containsRelease(releases, doesNotContain.ID)
	assert.False(t, result)
}

func TestGetLatestRelease(t *testing.T) {
	expectedRelease := models.Version{
		ID:     3333,
		SemVer: "v1.3.0",
	}
	firstRelease := models.Version{
		ID:     1111,
		SemVer: "v1.1.0",
	}
	secondRelease := models.Version{
		ID:     2222,
		SemVer: "v1.2.0",
	}
	releases := []models.Version{
		firstRelease,
		secondRelease,
		expectedRelease,
	}
	result := getLatestRelease(releases)
	assert.Equal(t, result, expectedRelease)
	// validate in different order
	releases = []models.Version{
		secondRelease,
		expectedRelease,
		firstRelease,
	}
	result = getLatestRelease(releases)
	assert.Equal(t, result, expectedRelease)
}
