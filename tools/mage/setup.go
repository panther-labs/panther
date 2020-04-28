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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	// Use the commit from the latest tagged release of https://github.com/golang/tools/releases
	goimportsVersion = "5fc56a9" // gopls/v0.4.0

	golangciVersion  = "1.23.6"
	swaggerVersion   = "0.23.0"
	terraformVersion = "0.12.24"
)

var (
	setupDirectory       = filepath.Join(".", ".setup")
	pythonVirtualEnvPath = filepath.Join(setupDirectory, "venv")
	terraformPath        = filepath.Join(setupDirectory, "terraform")
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

	results := make(chan goroutineResult)
	count := 0

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"download go modules", installGoModules()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"download go-swagger", installSwagger(env)}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"download golangci-lint", installGolangCiLint(env)}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"download terraform", installTerraform(env)}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"pip install", installPythonEnv()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"npm install", installNodeModules()}
	}(results)

	logResults(results, "setup", 1, count, count)
}

// Fetch all Go modules needed for tests and compilation.
//
// "go test" and "go build" will do this automatically, but putting it in the setup flow allows it
// to happen in parallel with the rest of the downloads. Pre-installing modules also allows
// us to build Lambda functions in parallel.
func installGoModules() error {
	logger.Info("setup: download go modules...")

	if err := sh.Run("go", "mod", "download"); err != nil {
		return err
	}

	// goimports is needed for formatting but isn't importable (won't be in go.mod)
	return sh.Run("go", "get", "golang.org/x/tools/cmd/goimports@"+goimportsVersion)
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
	if err := sh.Run("curl", "-s", "-o", filepath.Join(downloadDir, "ci.tar.gz"), "-fL", url); err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}

	archive := filepath.Join(downloadDir, "ci.tar.gz")
	if err := sh.Run("tar", "-xzf", archive, "-C", downloadDir); err != nil {
		return fmt.Errorf("failed to extract %s: %v", archive, err)
	}

	// moving golangci-lint from download folder to setupDirectory
	src := filepath.Join(downloadDir, pkg, "golangci-lint")
	if err := os.Rename(src, binary); err != nil {
		return fmt.Errorf("failed to mv %s to %s: %v", src, binary, err)
	}

	// deleting download folder
	if err := os.RemoveAll(downloadDir); err != nil {
		logger.Warnf("failed to remove temp folder %s: %v", downloadDir, err)
	}
	return nil
}

func installTerraform(uname string) error {
	uname = strings.ToLower(uname)
	if output, err := sh.Output(terraformPath, "-version"); err == nil && strings.Contains(output, terraformVersion) {
		logger.Infof("setup: %s v%s is already installed", terraformPath, terraformVersion)
		return nil
	}

	pkg := fmt.Sprintf("terraform_%s_%s_amd64", terraformVersion, uname)
	url := fmt.Sprintf("https://releases.hashicorp.com/terraform/%s/%s.zip", terraformVersion, pkg)
	archive := filepath.Join(setupDirectory, "terraform.zip")
	if err := sh.Run("curl", "-s", "-o", archive, "-fL", url); err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}

	if err := sh.Run("unzip", archive, "-d", setupDirectory); err != nil {
		return fmt.Errorf("failed to unzip %s: %v", archive, err)
	}

	if err := os.Remove(archive); err != nil {
		logger.Warnf("failed to remove %s after unpacking: %v", archive, err)
	}

	return nil
}

// Install the Python virtual env
func installPythonEnv() error {
	// Create .setup/venv if it doesn't already exist
	if info, err := os.Stat(pythonVirtualEnvPath); err == nil && info.IsDir() {
		if runningInCI() {
			// If .setup/venv already exists in CI, it must have been restored from the cache.
			logger.Info("setup: skipping pip install")
			return nil
		}
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
	if _, err := os.Stat("node_modules"); err == nil && runningInCI() {
		// In CI, if node_modules already exist, they must have been restored from the cache.
		// Stop early (otherwise, npm install takes ~10 seconds to figure out it has nothing to do).
		logger.Info("setup: skipping npm install")
		return nil
	}

	logger.Info("setup: npm install...")
	args := []string{"install", "--no-progress", "--no-audit"}
	if !mg.Verbose() {
		args = append(args, "--silent")
	}
	return sh.Run("npm", args...)
}
