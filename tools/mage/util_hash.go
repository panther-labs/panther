package mage

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
	"crypto/md5" // nolint:gosec
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Compute MD5 checksum of file contents.
func fileMD5(path string) ([16]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return [16]byte{}, fmt.Errorf("readFile %s: %v", path, err)
	}

	// nolint:gosec
	// Benchmarking shows MD5 is almost twice as fast as SHA2 and we don't need cryptographic guarantees here.
	return md5.Sum(data), nil
}

// Hash every file in the given directory
//
// Returns map from file path => MD5 sum
func fileHashMap(roots ...string) (map[string][16]byte, error) {
	result := make(map[string][16]byte)

	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("stat %s: %v", path, err)
			}

			if !info.IsDir() {
				result[path], err = fileMD5(path)
				if err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Hash every "source" file in the repo to check for diffs before vs after formatting.
//
// Excludes: .idea, .git, .setup, docs (fmt doesn't touch docs), keys, node_modules, out, etc
func sourceHashes() (map[string][16]byte, error) {
	topLevel, err := filepath.Glob("*.{json,md,go,yml}")
	if err != nil {
		return nil, fmt.Errorf("glob failed: %v", err)
	}

	// We don't want to waste time hashing files that we don't care about
	roots := append(topLevel, ".circleci", ".github", "api", "build", "cmd", "deployments",
		"docs", "internal", "pkg", "tools", "web")
	return fileHashMap(roots...)
}

// Return a list of file paths that are different between the two hash maps.
//
// Paths are prefixed with '~ ' if modified, '+ ' if added, '- ' if removed
func fileDiffs(before, after map[string][16]byte) []string {
	var diffs []string
	for path, hash := range before {
		afterHash, ok := after[path]

		if ok {
			// exists in both, did the contents change?
			if hash != afterHash {
				diffs = append(diffs, "~ "+path)
			}
		} else {
			// doesn't exist afterward
			diffs = append(diffs, "- "+path)
		}
	}

	// Optimization: if there are no diffs yet and the two sets have the same number of elements,
	// there can't be any new files and we don't have to traverse the second set.
	if len(diffs) == 0 && len(before) == len(after) {
		return nil
	}

	// Check for added files
	for path := range after {
		if _, ok := before[path]; !ok {
			diffs = append(diffs, "+ "+path)
		}
	}

	return diffs
}
