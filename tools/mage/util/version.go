package util

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
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/magefile/mage/sh"
)

var (
	version   string
	commitSha string
)

// Returns semantic version (from VERSION file). For example, "1.14.0-RC"
func Semver() string {
	// We use this rather than the git release tag because the VERSION file is tied to the commit,
	// whereas tags can be changed at any time (and don't always exist in every branch).
	if version == "" {
		s := strings.TrimSpace(string(MustReadFile("VERSION")))
		version = semver.MustParse(s).String() // make sure it is a valid semver cause it is used throughout Panther
	}
	return version
}

// Returns short commit string. For example, "64391f1e"
func CommitSha() string {
	if commitSha == "" {
		var err error
		commitSha, err = sh.Output("git", "rev-parse", "--short", "HEAD")
		if err != nil {
			panic(fmt.Errorf("failed to find most recent commit: %s", err))
		}
	}
	return commitSha
}
