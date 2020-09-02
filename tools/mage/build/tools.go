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
	"github.com/panther-labs/panther/tools/mage"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/mage/util"
)


// Lambda Compile Go Lambda function source
func (b Build) Lambda() {
	if err := b.lambda(); err != nil {
		mage.log.Fatal(err)
	}
}

// "go build" in parallel for each Lambda function.
//
// If you don't already have all go modules downloaded, this may fail because each goroutine will
// automatically modify the go.mod/go.sum files which will cause conflicts with itself.
//
// Run "go mod download" or "mage setup" before building to download the go modules.
// If you're adding a new module, run "go get ./..." before building to fetch the new module.
func (b Build) lambda() error {
	var packages []string
	util.Walk("internal", func(path string, info os.FileInfo) {
		if info.IsDir() && strings.HasSuffix(path, "main") {
			packages = append(packages, path)
		}
	})

	mage.log.Infof("build:lambda: compiling %d Go Lambda functions (internal/.../main) using %s",
		len(packages), runtime.Version())

	for _, pkg := range packages {
		if err := buildLambdaPackage(pkg); err != nil {
			return err
		}
	}

	return nil
}

func buildLambdaPackage(pkg string) error {
	targetDir := filepath.Join("out", "bin", pkg)
	binary := filepath.Join(targetDir, "main")
	var buildEnv = map[string]string{"GOARCH": "amd64", "GOOS": "linux"}

	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("failed to create %s directory: %v", targetDir, err)
	}
	if err := sh.RunWith(buildEnv, "go", "build", "-p", "1", "-ldflags", "-s -w", "-o", targetDir, "./"+pkg); err != nil {
		return fmt.Errorf("go build %s failed: %v", binary, err)
	}

	return nil
}

// Tools Compile devtools and opstools
func (b Build) Tools() {
	if err := b.tools(); err != nil {
		mage.log.Fatal(err)
	}
}

func (b Build) tools() error {
	// cross compile so tools can be copied to other machines easily
	buildEnvs := []map[string]string{
		// darwin:arm is not compatible
		{"GOOS": "darwin", "GOARCH": "amd64"},
		{"GOOS": "linux", "GOARCH": "amd64"},
		{"GOOS": "linux", "GOARCH": "arm"},
		{"GOOS": "windows", "GOARCH": "amd64"},
		{"GOOS": "windows", "GOARCH": "arm"},
	}

	var paths []string
	util.Walk("cmd", func(path string, info os.FileInfo) {
		if !info.IsDir() && filepath.Base(path) == "main.go" {
			paths = append(paths, path)
		}
	})

	for _, path := range paths {
		parts := strings.SplitN(path, `/`, 3)
		// E.g. "out/bin/cmd/devtools/" or "out/bin/cmd/opstools"
		outDir := filepath.Join("out", "bin", parts[0], parts[1])

		// used in tools to check/display which Panther version was compiled
		setVersionVar := fmt.Sprintf("-X 'main.version=%s'", util.RepoVersion())

		mage.log.Infof("build:tools: compiling %s to %s with %d os/arch combinations",
			path, outDir, len(buildEnvs))
		for _, env := range buildEnvs {
			// E.g. "requeue-darwin-amd64"
			binaryName := filepath.Base(filepath.Dir(path)) + "-" + env["GOOS"] + "-" + env["GOARCH"]
			if env["GOOS"] == "windows" {
				binaryName += ".exe"
			}

			err := sh.RunWith(env, "go", "build",
				"-ldflags", "-s -w "+setVersionVar,
				"-o", filepath.Join(outDir, binaryName), "./"+path)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Generate CloudFormation: deployments/dashboards.yml and out/deployments/
func (b Build) Cfn() {
	if err := b.cfn(); err != nil {
		mage.log.Fatal(err)
	}
}

func (b Build) cfn() error {
	if err := mage.embedAPISpec(); err != nil {
		return err
	}

	return mage.generateDashboards()
}
