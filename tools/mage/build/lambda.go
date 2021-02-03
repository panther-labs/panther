package build

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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/mage/logger"
)

// "go build" sequentially for each Lambda function.
//
// This function is not used during the deploy process - each function is built and uploaded
// individually during the packaging.
func Lambda() error {
	log := logger.Build("[build:lambda]")

	var packages []string
	if err := filepath.Walk("internal", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && strings.HasSuffix(path, "main") {
			packages = append(packages, path)
		}
		return nil
	}); err != nil {
		return err
	}

	log.Infof("compiling %d Go Lambda functions (internal/.../main) using %s",
		len(packages), runtime.Version())

	for _, pkg := range packages {
		if _, err := LambdaPackage(pkg); err != nil {
			return err
		}
	}

	return nil
}

// Build a binary for a single Lambda function, returning (binary path, error)
func LambdaPackage(pkg string) (string, error) {
	targetDir := filepath.Join("out", "bin", pkg)
	binary := filepath.Join(targetDir, "main")
	var buildEnv = map[string]string{"GOARCH": "amd64", "GOOS": "linux"}

	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return binary, fmt.Errorf("failed to create %s directory: %v", targetDir, err)
	}
	if err := sh.RunWith(buildEnv, "go", "build", "-ldflags", "-s -w", "-o", targetDir, "./"+pkg); err != nil {
		return binary, fmt.Errorf("go build %s failed: %v", binary, err)
	}

	return binary, nil
}
