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
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/mage/clients"
)

var gitVersion string

// Return full Panther version string, e.g. v1.10.0-master-5c2a8a76-dirty
//
// The base version ("v1.10.0") comes from the top-level VERSION file.
// This is followed by the current branch name ("master"),
// and then the last commit on the branch ("5c2a8a76").
// If there are local uncommitted changes, a "-dirty" suffix will be added.
func RepoVersion() string {
	if gitVersion != "" {
		return gitVersion
	}

	// Load base version from the top-level VERSION file, e.g. "1.10.0"
	//
	// We use this rather than the git release tag because the VERSION file is tied to the commit,
	// whereas tags can be changed at any time (and don't always exist in every branch).
	baseVersion := strings.TrimSpace(string(MustReadFile("VERSION")))

	// "git branch --show-current" works for Git 2.22+, but this should work on older versions:
	branch, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		panic(fmt.Errorf("failed to get name of current branch: %s", err))
	}

	commit, err := sh.Output("git", "rev-parse", "--short", "HEAD")
	if err != nil {
		panic(fmt.Errorf("failed to find most recent commit: %s", err))
	}

	gitVersion = fmt.Sprintf("v%s-%s-%s", baseVersion, branch, commit)

	// If there are uncommitted local changes, add a "-dirty" suffix
	if err := sh.Run("git", "diff", "--quiet"); err != nil {
		if strings.HasSuffix(err.Error(), "failed with exit code 1") {
			gitVersion += "-dirty"
		} else {
			panic(fmt.Errorf("git diff failed: %s", err))
		}
	}

	return gitVersion
}

// Find the most recent published version of Panther in S3, e.g. "1.7.1"
//
// This provides an alternative to checking the git tags in the repo.
func LatestPublishedVersion() (string, error) {
	bucket := PublicAssetsBucket(clients.Region())
	input := &s3.ListObjectsV2Input{
		Bucket: &bucket,
		// Packaged assets are hex and will not start with 'v'.
		// This will match only published master templates, e.g. "v1.7.1/master.yml"
		Prefix: aws.String("v"),
	}

	// Sorting versions by string is not sufficient ("v1.10.0" < "v1.3.0")
	// Instead, keep track of the semver components
	type semver struct {
		major int
		minor int
		patch string // could be "0-beta"
	}
	var versions []semver

	err := clients.S3().ListObjectsV2Pages(input, func(page *s3.ListObjectsV2Output, _ bool) bool {
		for _, object := range page.Contents {
			if strings.HasSuffix(*object.Key, "panther.yml") {
				// "v1.7.1/panther.yml" => "1.7.1"
				version := strings.TrimPrefix(*object.Key, "v")
				version = strings.TrimSuffix(version, "/panther.yml")
				split := strings.Split(version, ".")

				versions = append(versions, semver{
					major: MustParseInt(split[0]),
					minor: MustParseInt(split[1]),
					patch: split[2],
				})
			}
		}
		return true
	})
	if err != nil {
		return "", err
	}

	sort.Slice(versions, func(i, j int) bool {
		if versions[i].major != versions[j].major {
			return versions[i].major < versions[j].major
		}
		if versions[i].minor != versions[j].minor {
			return versions[i].minor < versions[j].minor
		}
		return versions[i].patch < versions[j].patch
	})

	latest := versions[len(versions)-1]
	return fmt.Sprintf("%d.%d.%s", latest.major, latest.minor, latest.patch), nil
}

func MustParseInt(x string) int {
	result, err := strconv.Atoi(x)
	if err != nil {
		panic(fmt.Errorf("expected int: %s: %v", x, err))
	}
	return result
}
