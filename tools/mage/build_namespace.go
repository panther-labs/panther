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
	"path"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

	"github.com/panther-labs/panther/pkg/shutil"
)

var buildEnv = map[string]string{"GOARCH": "amd64", "GOOS": "linux"}

// Build contains targets for compiling source code.
type Build mg.Namespace

// API Generate Go client/models from Swagger specs in api/
func (b Build) API() error {
	specs, err := filepath.Glob("api/gateway/*/api.yml")
	if err != nil {
		return err
	}

	for _, spec := range specs {
		needsRebuilt, err := apiNeedsRebuilt(spec)
		if err != nil {
			return err
		}

		if !needsRebuilt {
			if mg.Verbose() {
				fmt.Printf("build:api: %s client/models up to date\n", spec)
			}
			continue
		}

		if !mg.Verbose() {
			fmt.Println("build:api: swagger generate " + spec)
		}

		// If an API model is deleted, the generated file will still exist after "swagger generate".
		// So we remove existing client/ and models/ directories before re-generating.
		dir := path.Dir(spec)
		if err := os.RemoveAll(path.Join(dir, "client")); err != nil {
			return err
		}
		if err := os.RemoveAll(path.Join(dir, "models")); err != nil {
			return err
		}

		args := []string{"generate", "client", "-q", "-t", path.Dir(spec), "-f", spec}
		if err := sh.Run("swagger", args...); err != nil {
			return err
		}

		if err := fmtLicenseGroup(agplSource, dir); err != nil {
			return err
		}
	}

	return nil
}

// Returns true if the generated client + models are older than the given client spec
func apiNeedsRebuilt(spec string) (bool, error) {
	clientNeedsUpdate, err := target.Dir(path.Join(path.Dir(spec), "client"), spec)
	if err != nil {
		return true, err
	}

	modelsNeedUpdate, err := target.Dir(path.Join(path.Dir(spec), "models"), spec)
	if err != nil {
		return true, err
	}

	return clientNeedsUpdate || modelsNeedUpdate, nil
}

// Lambda Compile all Lambda function source
func (b Build) Lambda() error {
	mg.Deps(b.API)

	var packages []string
	err := filepath.Walk("internal", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && strings.HasSuffix(path, "main") {
			packages = append(packages, path)
		}
		return err
	})
	if err != nil {
		return err
	}

	fmt.Printf("build:lambda: go build internal/*/main (%d binaries)\n", len(packages))
	for _, pkg := range packages {
		if err := buildPackage(pkg); err != nil {
			return err
		}
	}

	return nil
}

func buildPackage(pkg string) error {
	targetDir := path.Join("out", "bin", pkg)
	binary := path.Join(targetDir, "main")
	oldInfo, statErr := os.Stat(binary)
	oldHash, hashErr := shutil.SHA256(binary)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	if err := sh.RunWith(buildEnv, "go", "build", "-ldflags", "-s -w", "-o", targetDir, "./"+pkg); err != nil {
		return err
	}

	if statErr == nil && hashErr == nil {
		if hash, err := shutil.SHA256(binary); err == nil && hash == oldHash {
			// Optimization - if the binary contents haven't changed, reset the last modified time.
			// "aws cloudformation package" re-uploads any binary whose modification time has changed,
			// even if the contents are identical. So this lets us skip any unmodified binaries, which can
			// significantly reduce the total deployment time if only one or two functions changed.
			//
			// With 5 unmodified Lambda functions, deploy:app went from 146s => 109s with this fix.
			if mg.Verbose() {
				fmt.Printf("build:lambda: %s unchanged, reverting timestamp\n", binary)
			}
			modTime := oldInfo.ModTime()
			return os.Chtimes(binary, modTime, modTime)
		}
	}

	return nil
}
