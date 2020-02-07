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
	golangciVersion = "1.22.2"
	swaggerVersion  = "0.21.0"
)

var (
	setupDirectory       = filepath.Join(".", ".setup")
	pythonVirtualEnvPath = filepath.Join(setupDirectory, "venv")
)

// Setup contains targets for installing development / CI dependencies
type Setup mg.Namespace

// All Install all development dependencies
func (s Setup) All() {
	s.Go()
	s.Python()
	s.Web()
}

// Go Install goimports, go-swagger, and golangci-lint
func (Setup) Go() {
	// Some libraries are only needed for development, not for CI
	if !isRunningInCI() {
		logger.Info("setup: installing goimports")
		if err := sh.RunV("go", "get", "golang.org/x/tools/cmd/goimports"); err != nil {
			logger.Fatalf("go get goimports failed: %v", err)
		}
	}

	env, err := sh.Output("uname")
	if err != nil {
		logger.Fatalf("couldn't determine environment: %v", err)
	}
	if err = installSwagger(env); err != nil {
		logger.Fatal(err)
	}
	if err = installGolangCiLint(env); err != nil {
		logger.Fatal(err)
	}
}

// Python Install the Python virtual env
func (Setup) Python() {
	logger.Info("setup: installing python3 env to " + pythonVirtualEnvPath)
	if err := os.RemoveAll(pythonVirtualEnvPath); err != nil {
		logger.Fatalf("failed to remove existing %s: %v", pythonVirtualEnvPath, err)
	}

	if err := sh.RunV("python3", "-m", "venv", pythonVirtualEnvPath); err != nil {
		logger.Fatalf("failed to create venv %s: %v", pythonVirtualEnvPath, err)
	}

	args := []string{"install", "-r", "requirements.txt"}
	if !mg.Verbose() {
		args = append(args, "--quiet")
	}
	if err := sh.RunV(pythonLibPath("pip3"), args...); err != nil {
		logger.Fatalf("pip installation failed: %v", err)
	}
}

// Web Npm install
func (Setup) Web() {
	if err := sh.RunV("npm", "i"); err != nil {
		logger.Fatalf("npm install failed: %v", err)
	}
}

func installSwagger(uname string) error {
	logger.Info("setup: installing go-swagger")
	if err := os.MkdirAll(setupDirectory, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create setup directory %s: %v", setupDirectory, err)
	}

	url := fmt.Sprintf("https://github.com/go-swagger/go-swagger/releases/download/v%s/swagger_%s_amd64",
		swaggerVersion, strings.ToLower(uname))
	binary := filepath.Join(setupDirectory, "swagger")
	if err := sh.RunV("curl", "-o", binary, "-fL", url); err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}

	if err := sh.RunV("chmod", "+x", binary); err != nil {
		return fmt.Errorf("failed to make %s executable: %v", binary, err)
	}
	return nil
}

func installGolangCiLint(uname string) error {
	logger.Info("setup: installing golangci-lint")
	downloadDir := filepath.Join(setupDirectory, "golangci")
	if err := os.MkdirAll(downloadDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create temporary %s: %v", downloadDir, err)
	}

	pkg := fmt.Sprintf("golangci-lint-%s-%s-amd64", golangciVersion, strings.ToLower(uname))
	url := fmt.Sprintf("https://github.com/golangci/golangci-lint/releases/download/v%s/%s.tar.gz",
		golangciVersion, pkg)
	if err := sh.RunV("curl", "-o", filepath.Join(downloadDir, "ci.tar.gz"), "-fL", url); err != nil {
		return fmt.Errorf("failed to download %s: %v", url, err)
	}

	archive := filepath.Join(downloadDir, "ci.tar.gz")
	if err := sh.RunV("tar", "-xzvf", archive, "-C", downloadDir); err != nil {
		return fmt.Errorf("failed to extract %s: %v", archive, err)
	}

	// moving golangci-lint from download folder to setupDirectory
	src, dst := filepath.Join(downloadDir, pkg, "golangci-lint"), filepath.Join(setupDirectory, "golangci-lint")
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("failed to mv %s to %s: %v", src, dst, err)
	}

	// deleting download folder
	if err := os.RemoveAll(downloadDir); err != nil {
		logger.Warnf("failed to remove temp folder %s", downloadDir)
	}
	return nil
}
