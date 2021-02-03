package setup

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

	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

const (
	// Use the commit from the latest tagged release of https://github.com/golang/tools/releases
	goimportsVersion = "d58e364" // gopls/v0.6.5

	golangciVersion  = "1.36.0"
	terraformVersion = "0.14.5"
)

var log = logger.Build("[setup]")

// Install all build and development dependencies
func Setup() error {
	env, err := sh.Output("uname")
	if err != nil {
		return fmt.Errorf("couldn't determine environment: %v", err)
	}
	if err := os.MkdirAll(util.SetupDir, 0700); err != nil {
		return fmt.Errorf("failed to create setup directory %s: %v", util.SetupDir, err)
	}

	if err := installGolangCiLint(env); err != nil {
		return err
	}
	if err := installTerraform(env); err != nil {
		return err
	}
	if err := installGoModules(); err != nil {
		return err
	}
	if err := installPythonEnv(); err != nil {
		return err
	}
	if err := installNodeModules(); err != nil {
		return err
	}

	return nil
}

// Fetch all Go modules needed for tests and compilation.
//
// "go test" and "go build" will do this automatically, but putting it in the setup flow allows it
// to happen in parallel with the rest of the downloads. Pre-installing modules also allows
// us to build Lambda functions in parallel.
func installGoModules() error {
	log.Info("downloading go modules...")

	if err := sh.Run("go", "mod", "download"); err != nil {
		return err
	}

	// goimports is needed for formatting but isn't importable
	if err := sh.Run("go", "get", "golang.org/x/tools/cmd/goimports@"+goimportsVersion); err != nil {
		return err
	}

	// prevent dirty repo state - run the same tidy command we use during formatting to
	// standardize the final go.mod file
	return sh.Run("go", "mod", "tidy")
}

// Download golangci-lint if it hasn't been already
func installGolangCiLint(uname string) error {
	if output, err := sh.Output(util.GoLinter, "--version"); err == nil && strings.Contains(output, golangciVersion) {
		log.Infof("%s v%s is already installed", util.GoLinter, golangciVersion)
		return nil
	}

	log.Infof("downloading golangci-lint v%s...", golangciVersion)
	downloadDir := filepath.Join(util.SetupDir, "golangci")
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
	if err := os.Rename(src, util.GoLinter); err != nil {
		return fmt.Errorf("failed to mv %s to %s: %v", src, util.GoLinter, err)
	}

	// deleting download folder
	if err := os.RemoveAll(downloadDir); err != nil {
		log.Warnf("failed to remove temp folder %s: %v", downloadDir, err)
	}
	return nil
}

func installTerraform(uname string) error {
	uname = strings.ToLower(uname)
	if output, err := sh.Output(util.Terraform, "-version"); err == nil && strings.Contains(output, terraformVersion) {
		log.Infof("%s v%s is already installed", util.Terraform, terraformVersion)
		return nil
	}

	pkg := fmt.Sprintf("terraform_%s_%s_amd64", terraformVersion, uname)
	url := fmt.Sprintf("https://releases.hashicorp.com/terraform/%s/%s.zip", terraformVersion, pkg)
	archive := filepath.Join(util.SetupDir, "terraform.zip")
	if err := sh.Run("curl", "-s", "-o", archive, "-fL", url); err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}

	if err := sh.Run("unzip", archive, "-d", util.SetupDir); err != nil {
		return fmt.Errorf("failed to unzip %s: %v", archive, err)
	}

	if err := os.Remove(archive); err != nil {
		log.Warnf("failed to remove %s after unpacking: %v", archive, err)
	}

	return nil
}

// Install the Python virtual env
func installPythonEnv() error {
	// Create .setup/venv if it doesn't already exist
	if info, err := os.Stat(util.PyEnv); err == nil && info.IsDir() {
		if util.IsRunningInCI() {
			// If .setup/venv already exists in CI, it must have been restored from the cache.
			log.Info("skipping pip install")
			return nil
		}
	} else {
		if err := sh.Run("python3", "-m", "venv", util.PyEnv); err != nil {
			return fmt.Errorf("failed to create venv %s: %v", util.PyEnv, err)
		}
	}

	// pip install requirements
	log.Infof("pip install requirements.txt to %s...", util.PyEnv)
	args := []string{"install", "-r", "requirements.txt"}
	if !mg.Verbose() {
		args = append(args, "--quiet")
	}
	if err := sh.Run(util.PipPath("pip3"), args...); err != nil {
		return fmt.Errorf("pip installation failed: %v", err)
	}

	// update cfn linter specs (cnf-lint is a python package)
	if err := sh.RunV(util.PipPath("cfn-lint"), "--update-specs"); err != nil {
		return err
	}

	return nil
}

// Install npm modules
func installNodeModules() error {
	if _, err := os.Stat(util.NpmDir); err == nil && util.IsRunningInCI() {
		// In CI, if node_modules already exist, they must have been restored from the cache.
		// Stop early (otherwise, npm install takes ~10 seconds to figure out it has nothing to do).
		log.Info("skipping npm install")
		return nil
	}

	// 'npm ci' is a lightweight alternative to `npm install` that's faster since it omits
	// lots of user-oriented features. In CIs, it's the recommended way to install packages
	var args []string
	if util.IsRunningInCI() {
		log.Info("npm ci...")
		args = []string{"ci", "--no-progress", "--no-audit"}
	} else {
		log.Info("npm install...")
		args = []string{"install", "--no-progress", "--no-audit"}
	}

	if !mg.Verbose() {
		args = append(args, "--silent")
	}
	return sh.Run("npm", args...)
}
