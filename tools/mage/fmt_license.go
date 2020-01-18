package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
)

const (
	agplSource       = "docs/LICENSE_HEADER_AGPL.txt"
	apacheSource     = "docs/LICENSE_HEADER_APACHE.txt"
	commercialSource = "docs/LICENSE_HEADER_PANTHER.txt"
)

var (
	// Most open-source code is AGPL
	agplPaths = []string{"api", "build", "deployments", "internal", "tools", "web/scripts", "web/src", "magefile.go"}

	// Standalone Go packages are Apache
	apachePaths = []string{"pkg"}

	// Enterprise closed-source code is Panther commercial license
	commercialPaths = []string{"enterprise"}
)

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

// Add license headers to all applicable source files.
func fmtLicense() error {
	if err := fmtLicenseGroup(agplSource, agplPaths...); err != nil {
		return err
	}
	if err := fmtLicenseGroup(apacheSource, apachePaths...); err != nil {
		return err
	}
	if info, err := os.Stat("enterprise"); err == nil && info.IsDir() {
		return fmtLicenseGroup(commercialSource, commercialPaths...)
	}

	return nil
}

// Add one type of license header to a group of files.
func fmtLicenseGroup(sourceFile string, basePaths ...string) error {
	if mg.Verbose() {
		fmt.Println("fmt: license:", sourceFile, basePaths)
	}

	rawHeader, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		return err
	}
	header := strings.TrimSpace(string(rawHeader))

	asteriskLicense := "/**\n" + commentEachLine(" *", header) + "\n */"
	hashtagLicense := commentEachLine("#", header)

	for _, root := range basePaths {
		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil // skip directories
			}
			return addFileLicense(path, asteriskLicense, hashtagLicense)
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func addFileLicense(path, asteriskLicense, hashtagLicense string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return modifyFile(path, func(contents string) string {
			return addGoLicense(contents, asteriskLicense)
		})
	case ".js", ".ts", ".tsx":
		return modifyFile(path, func(contents string) string {
			return prependHeader(contents, asteriskLicense)
		})
	case ".py", ".sh", ".yml", ".yaml":
		return modifyFile(path, func(contents string) string {
			return prependHeader(contents, hashtagLicense)
		})
	case "":
		// empty extension - might be called "Dockerfile"
		if strings.ToLower(filepath.Base(path)) == "dockerfile" {
			return modifyFile(path, func(contents string) string {
				return prependHeader(contents, hashtagLicense)
			})
		}
	}

	return nil
}

// Rewrite file contents on disk with the given modifier function.
func modifyFile(path string, modifier func(string) string) error {
	contentBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	contents := string(contentBytes)

	newContents := modifier(contents)
	if newContents == contents {
		return nil // no changes required
	}

	return ioutil.WriteFile(path, []byte(newContents), 0644)
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
