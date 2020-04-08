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
)

const (
	golangciVersion = "1.23.6"
	swaggerVersion  = "0.23.0"
)

var (
	setupDirectory       = filepath.Join(".", ".setup")
	pythonVirtualEnvPath = filepath.Join(setupDirectory, "venv")
)

// Setup Install all build and development dependencies
func Setup() {
	env, err := sh.Output("uname")
	if err != nil {
		logger.Fatalf("couldn't determine environment: %v", err)
	}
	if err := os.MkdirAll(setupDirectory, os.ModePerm); err != nil {
		logger.Fatalf("failed to create setup directory %s: %v", setupDirectory, err)
	}

	type installResult struct {
		summary string
		err     error
	}
	results := make(chan installResult)
	count := 0

	count++
	go func(c chan installResult) {
		c <- installResult{"go get modules", installGoModules()}
	}(results)

	count++
	go func(c chan installResult) {
		c <- installResult{"download go-swagger", installSwagger(env)}
	}(results)

	count++
	go func(c chan installResult) {
		c <- installResult{"download golangci-lint", installGolangCiLint(env)}
	}(results)

	count++
	go func(c chan installResult) {
		c <- installResult{"pip install", installPythonEnv()}
	}(results)

	count++
	go func(c chan installResult) {
		c <- installResult{"npm install", installNodeModules()}
	}(results)

	// Print the result of each goroutine as it finishes
	errors := 0
	for i := 0; i < count; i++ {
		r := <-results
		if r.err == nil {
			logger.Infof("    √ %s finished", r.summary)
		} else {
			logger.Errorf("    X %s failed: %v", r.summary, r.err)
			errors++
		}
	}

	if errors > 0 {
		logger.Fatalf("setup failed: %s total errors", errors)
	}
}

// Fetch all Go modules needed for tests and compilation.
//
// "go test" and "go build" will do this automatically, but putting it in the setup flow allows it
// to happen in parallel with the rest of the downloads.
func installGoModules() error {
	logger.Info("setup: go get modules...")

	// goimports is needed for formatting but won't be listed as an explicit dependency
	return sh.Run("go", "get", "-t", "golang.org/x/tools/cmd/goimports", "./...")
}

// Download go-swagger if it hasn't been already
func installSwagger(uname string) error {
	binary := filepath.Join(setupDirectory, "swagger")
	if output, err := sh.Output(binary, "version"); err == nil && strings.Contains(output, swaggerVersion) {
		logger.Infof("setup: %s v%s is already installed", binary, swaggerVersion)
		return nil
	}

	logger.Infof("setup: downloading go-swagger v%s...", swaggerVersion)
	url := fmt.Sprintf("https://github.com/go-swagger/go-swagger/releases/download/v%s/swagger_%s_amd64",
		swaggerVersion, strings.ToLower(uname))
	if err := sh.Run("curl", "-s", "-o", binary, "-fL", url); err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}

	if err := sh.Run("chmod", "+x", binary); err != nil {
		return fmt.Errorf("failed to make %s executable: %v", binary, err)
	}

	return nil
}

// Download golangci-lint if it hasn't been already
func installGolangCiLint(uname string) error {
	binary := filepath.Join(setupDirectory, "golangci-lint")
	if output, err := sh.Output(binary, "--version"); err == nil && strings.Contains(output, golangciVersion) {
		logger.Infof("setup: %s v%s is already installed", binary, golangciVersion)
		return nil
	}

	logger.Infof("setup: downloading golangci-lint v%s...", golangciVersion)
	downloadDir := filepath.Join(setupDirectory, "golangci")
	if err := os.MkdirAll(downloadDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create temporary %s: %v", downloadDir, err)
	}

	pkg := fmt.Sprintf("golangci-lint-%s-%s-amd64", golangciVersion, strings.ToLower(uname))
	url := fmt.Sprintf("https://github.com/golangci/golangci-lint/releases/download/v%s/%s.tar.gz",
		golangciVersion, pkg)
	if err := sh.RunV("curl", "-s", "-o", filepath.Join(downloadDir, "ci.tar.gz"), "-fL", url); err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}

	archive := filepath.Join(downloadDir, "ci.tar.gz")
	if err := sh.RunV("tar", "-xzvf", archive, "-C", downloadDir); err != nil {
		return fmt.Errorf("failed to extract %s: %v", archive, err)
	}

	// moving golangci-lint from download folder to setupDirectory
	src := filepath.Join(downloadDir, pkg, "golangci-lint")
	if err := os.Rename(src, binary); err != nil {
		return fmt.Errorf("failed to mv %s to %s: %v", src, binary, err)
	}

	// deleting download folder
	if err := os.RemoveAll(downloadDir); err != nil {
		logger.Warnf("failed to remove temp folder %s", downloadDir)
	}
	return nil
}

// Install the Python virtual env
func installPythonEnv() error {
	// Create .setup/venv if it doesn't already exist
	if info, err := os.Stat(pythonVirtualEnvPath); err == nil && info.IsDir() {
		logger.Debugf("setup: %s already exists", pythonVirtualEnvPath)
	} else {
		if err := sh.Run("python3", "-m", "venv", pythonVirtualEnvPath); err != nil {
			return fmt.Errorf("failed to create venv %s: %v", pythonVirtualEnvPath, err)
		}
	}

	// pip install requirements
	logger.Infof("setup: pip install requirements.txt to %s...", pythonVirtualEnvPath)
	args := []string{"install", "-r", "requirements.txt"}
	if !mg.Verbose() {
		args = append(args, "--quiet")
	}
	if err := sh.Run(pythonLibPath("pip3"), args...); err != nil {
		return fmt.Errorf("pip installation failed: %v", err)
	}

	return nil
}

// Install npm modules
func installNodeModules() error {
	logger.Info("setup: npm install...")
	return sh.Run("npm", "i", "--no-progress", "--silent")
}
