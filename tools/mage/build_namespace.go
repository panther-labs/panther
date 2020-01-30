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
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/pkg/shutil"
)

const swaggerGlob = "api/gateway/*/api.yml"

var buildEnv = map[string]string{"GOARCH": "amd64", "GOOS": "linux"}

// Build contains targets for compiling source code.
type Build mg.Namespace

// API Generate Go client/models from Swagger specs in api/
func (b Build) API() {
	specs, err := filepath.Glob(swaggerGlob)
	if err != nil {
		fatal(fmt.Errorf("failed to glob %s: %v", swaggerGlob, err))
	}

	logger.Infof("build:api: generating Go SDK for %d APIs (%s)", len(specs), swaggerGlob)
	for _, spec := range specs {
		// If an API model is deleted, the generated file will still exist after "swagger generate".
		// So we remove existing client/ and models/ directories before re-generating.
		dir := filepath.Dir(spec)
		client, models := filepath.Join(dir, "client"), filepath.Join(dir, "models")
		if err := os.RemoveAll(client); err != nil {
			fatal(fmt.Errorf("failed to reset %s: %v", client, err))
		}
		if err := os.RemoveAll(filepath.Join(dir, "models")); err != nil {
			fatal(fmt.Errorf("failed to reset %s: %v", models, err))
		}

		args := []string{"generate", "client", "-q", "-t", filepath.Dir(spec), "-f", spec}
		cmd := filepath.Join(setupDirectory, "swagger")
		if err := sh.Run(cmd, args...); err != nil {
			fatal(fmt.Errorf("%s %s failed: %v", cmd, strings.Join(args, " "), err))
		}

		// TODO - need to do full Go + license formatting for API files
	}
}

// Lambda Compile Go Lambda function source
func (b Build) Lambda() {
	mg.Deps(b.API)

	var packages []string
	walk("internal", func(path string, info os.FileInfo) {
		if info.IsDir() && strings.HasSuffix(path, "main") {
			packages = append(packages, path)
		}
	})

	logger.Infof("build:lambda: compiling %d Go Lambda functions (internal/.../main)", len(packages))
	for _, pkg := range packages {
		if err := buildPackage(pkg); err != nil {
			fatal(err)
		}
	}
}

func buildPackage(pkg string) error {
	targetDir := filepath.Join("out", "bin", pkg)
	binary := filepath.Join(targetDir, "main")
	oldInfo, statErr := os.Stat(binary)
	oldHash, hashErr := shutil.SHA256(binary)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory: %v", targetDir, err)
	}
	if err := sh.RunWith(buildEnv, "go", "build", "-ldflags", "-s -w", "-o", targetDir, "./"+pkg); err != nil {
		return fmt.Errorf("go build %s failed: %v", binary, err)
	}

	if statErr == nil && hashErr == nil {
		if hash, err := shutil.SHA256(binary); err == nil && hash == oldHash {
			// Optimization - if the binary contents haven't changed, reset the last modified time.
			// "aws cloudformation package" re-uploads any binary whose modification time has changed,
			// even if the contents are identical. So this lets us skip any unmodified binaries, which can
			// significantly reduce the total deployment time if only one or two functions changed.
			//
			// With 5 unmodified Lambda functions, deploy:app went from 146s => 109s with this fix.
			logger.Debugf("%s binary unchanged, reverting timestamp", binary)
			modTime := oldInfo.ModTime()
			if err = os.Chtimes(binary, modTime, modTime); err != nil {
				// Non-critical error - the build process can continue
				logger.Warnf("failed optimization: can't revert timestamp for %s: %v", binary, err)
			}
		}
	}

	return nil
}
