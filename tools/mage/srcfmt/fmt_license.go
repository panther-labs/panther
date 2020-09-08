package srcfmt

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
	"os"
	"path/filepath"
	"strings"

	"github.com/panther-labs/panther/tools/mage/util"
)

const agplSource = "docs/LICENSE_HEADER_AGPL.txt"

var licensePaths = []string{"api", "build", "cmd", "deployments", "internal", "pkg", "tools", "web", "magefile.go"}

// Add a comment character in front of each line in a block of license text.
func commentEachLine(prefix, text string) string {
	lines := strings.Split(text, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			result = append(result, prefix)
		} else {
			result = append(result, prefix+" "+line)
		}
	}

	return strings.Join(result, "\n")
}

// Add the license header to all applicable source files
func fmtLicenseAll() {
	fmtLicense(licensePaths...)
}

func fmtLicense(paths ...string) {
	log.Debugf("license header %s for %s", agplSource, strings.Join(paths, " "))
	header := strings.TrimSpace(string(util.MustReadFile(agplSource)))

	asteriskLicense := "/**\n" + commentEachLine(" *", header) + "\n */"
	hashtagLicense := commentEachLine("#", header)

	for _, root := range paths {
		util.MustWalk(root, func(path string, info os.FileInfo) error {
			if info.IsDir() {
				// some monorepo dirs have nested node_modules. Until NPM ships their "workspaces" feature,
				// we can't hoist all node modules in single folder at the project root. This prevents us
				// from wrongly adding headers to 3rd party modules
				if strings.Contains(path, "node_modules") {
					return filepath.SkipDir
				}
			} else {
				addFileLicense(path, asteriskLicense, hashtagLicense)
			}

			return nil
		})
	}
}

func addFileLicense(path, asteriskLicense, hashtagLicense string) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		licenseModifier(path, func(contents string) string {
			return addGoLicense(contents, asteriskLicense)
		})
	case ".js", ".ts", ".tsx":
		licenseModifier(path, func(contents string) string {
			return prependHeader(contents, asteriskLicense)
		})
	case ".py", ".sh", ".tf", ".yml", ".yaml":
		licenseModifier(path, func(contents string) string {
			return prependHeader(contents, hashtagLicense)
		})
	case "":
		// empty extension - might be called "Dockerfile"
		if strings.ToLower(filepath.Base(path)) == "dockerfile" {
			licenseModifier(path, func(contents string) string {
				return prependHeader(contents, hashtagLicense)
			})
		}
	}
}

// Rewrite file contents on disk with the given modifier function.
func licenseModifier(path string, modifier func(string) string) {
	contents := string(util.MustReadFile(path))
	newContents := modifier(contents)
	if newContents != contents {
		util.MustWriteFile(path, []byte(newContents))
	}
}

// Add the license to the given Go file contents if necessary, returning the modified body.
func addGoLicense(contents, asteriskLicense string) string {
	if strings.Contains(contents, asteriskLicense) {
		return contents
	}

	// Loop over each line looking for the package declaration.
	// Comments before the package statement must be preserved for godoc and +build declarations.
	var result []string
	foundPackage := false
	for _, line := range strings.Split(contents, "\n") {
		result = append(result, line)
		if !foundPackage && strings.HasPrefix(strings.TrimSpace(line), "package ") {
			result = append(result, "\n"+asteriskLicense)
			foundPackage = true
		}
	}

	return strings.Join(result, "\n")
}

// Prepend a header if it doesn't already exist, returning the modified file contents.
func prependHeader(contents, header string) string {
	if strings.Contains(contents, header) {
		return contents
	}
	return header + "\n\n" + contents
}
