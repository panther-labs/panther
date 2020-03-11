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
	"runtime"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

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
		logger.Fatalf("failed to glob %s: %v", swaggerGlob, err)
	}

	logger.Infof("build:api: generating Go SDK for %d APIs (%s)", len(specs), swaggerGlob)
	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatalf("failed to get current working directory: %v", err)
	}

	for _, spec := range specs {
		// Only regenerate the swagger SDK if needed - this allows deployments from a fresh clone
		// without needing to install Swagger and also makes subsequent deployments faster
		// (the compiled Go binary won't change)
		rebuild, err := apiNeedsRebuilt(spec)
		if err == nil && !rebuild {
			logger.Debugf("build:api: %s is up to date", spec)
			continue
		}

		// Swagger generates the wrong imports when running from the base directory, even with the
		// "-t" flag. So we have to change to each api/gateway directory before running swagger
		dir := filepath.Dir(spec)
		if err = os.Chdir(dir); err != nil {
			logger.Fatalf("failed to chdir %s: %v", dir, err)
		}

		start := time.Now().UTC()
		args := []string{"generate", "client", "-q", "-f", filepath.Base(spec)}
		cmd := filepath.Join(cwd, setupDirectory, "swagger")
		if _, err = os.Stat(cmd); err != nil {
			logger.Fatalf("%s not found (%v): run 'mage setup:all'", cmd, err)
		}

		if err := sh.Run(cmd, args...); err != nil {
			logger.Fatalf("%s %s failed: %v", cmd, strings.Join(args, " "), err)
		}

		// If an API model is removed, "swagger generate" will leave the Go file in place.
		// So we walk the generated directories and remove anything swagger didn't just write.
		handler := func(path string, info os.FileInfo) {
			if !info.IsDir() && info.ModTime().Before(start) {
				logger.Debugf("%s unmodified by swagger: removing", path)
				if err := os.Remove(path); err != nil {
					logger.Warnf("failed to remove deleted model %s: %v", path, err)
				}
			}
		}
		client, models := filepath.Join(dir, "client"), filepath.Join(dir, "models")
		walk(filepath.Base(client), handler)
		walk(filepath.Base(models), handler)

		// Add license and our formatting standard to the generated SDK.
		if err = os.Chdir(cwd); err != nil {
			logger.Fatalf("failed to chdir back to %s: %v", cwd, err)
		}
		fmtLicenseGroup(agplSource, client, models)
		gofmt(dir, client, models)
	}
}

// Returns true if the generated client + models are older than the given client spec
func apiNeedsRebuilt(spec string) (bool, error) {
	clientNeedsUpdate, err := target.Dir(filepath.Join(filepath.Dir(spec), "client"), spec)
	if err != nil {
		return true, err
	}

	modelsNeedUpdate, err := target.Dir(filepath.Join(filepath.Dir(spec), "models"), spec)
	if err != nil {
		return true, err
	}

	return clientNeedsUpdate || modelsNeedUpdate, nil
}

// Lambda Compile Go Lambda function source
func (b Build) Lambda() {
	if err := b.lambda(); err != nil {
		logger.Fatal(err)
	}
}

func (b Build) lambda() error {
	modified, err := target.Dir("out/bin/internal", "api", "internal", "pkg")
	if err == nil && !modified {
		// The source folders are older than all the compiled binaries - nothing has changed
		logger.Info("build:lambda: up to date")
		return nil
	}

	mg.Deps(b.API)

	var packages []string
	walk("internal", func(path string, info os.FileInfo) {
		if info.IsDir() && strings.HasSuffix(path, "main") {
			packages = append(packages, path)
		}
	})

	logger.Infof("build:lambda: compiling %d Go Lambda functions (internal/.../main) using %s",
		len(packages), runtime.Version())
	for _, pkg := range packages {
		if err := buildPackage(pkg); err != nil {
			return err
		}
	}

	return nil
}

// Opstools Compile Go ops tools from source
func (b Build) Opstools() {
	const (
		binDir    = "out/bin/opstools"
		sourceDir = "cmd/opstools"
	)

	if err := os.MkdirAll(binDir, 0755); err != nil {
		logger.Fatalf("failed to create %s directory: %v", binDir, err)
	}

	walk(sourceDir, func(path string, info os.FileInfo) {
		if !info.IsDir() && strings.HasSuffix(path, "main.go") {
			app := filepath.Dir(path)
			logger.Infof("build:opstools: compiling %s", app)
			// NOTE: passing nil in as env to get native compilation
			if err := sh.RunWith(nil, "go", "build", "-ldflags", "-s -w", "-o", binDir, "./"+app); err != nil {
				logger.Fatalf("go build %s failed: %v", path, err)
			}
		}
	})
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

// (Beta) Cfn Generate Glue CFN templates in out/deployments folder
func (b Build) Cfn() {
	// TODO Eventually change it so it generates all CFN templates that will be used
	// TODO Add a "build:all" target that just builds everything that will be deployed, but without triggering the actual deployment.
	if err := generateGlueTables(); err != nil {
		logger.Fatal(err)
	}
}
