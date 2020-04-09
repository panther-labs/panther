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
	"runtime"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/config"
)

const swaggerGlob = "api/gateway/*/api.yml"

var buildEnv = map[string]string{"GOARCH": "amd64", "GOOS": "linux"}

// Build contains targets for compiling source code.
type Build mg.Namespace

// API Generate API source files from GraphQL + Swagger
func (b Build) API() {
	specs, err := filepath.Glob(swaggerGlob)
	if err != nil {
		logger.Fatalf("failed to glob %s: %v", swaggerGlob, err)
	}

	logger.Infof("build:api: generating Go SDK for %d APIs (%s)", len(specs), swaggerGlob)

	cmd := filepath.Join(setupDirectory, "swagger")
	if _, err = os.Stat(cmd); err != nil {
		logger.Fatalf("%s not found (%v): run 'mage setup'", cmd, err)
	}

	for _, spec := range specs {
		dir := filepath.Dir(spec)
		client, models := filepath.Join(dir, "client"), filepath.Join(dir, "models")
		start := time.Now().UTC()

		args := []string{"generate", "client", "-q", "-f", spec, "-c", client, "-m", models, "-r", agplSource}
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
		walk(client, handler)
		walk(models, handler)
	}

	logger.Info("build:api: generating web typescript from graphql")
	if err := sh.Run("npm", "run", "graphql-codegen"); err != nil {
		logger.Fatalf("graphql generation failed: %v", err)
	}
}

// Lambda Compile Go Lambda function source
func (b Build) Lambda() {
	if err := b.lambda(); err != nil {
		logger.Fatal(err)
	}
}

func (b Build) lambda() error {
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

// Tools Compile devtools and opstools
func (b Build) Tools() {
	if err := b.tools(); err != nil {
		logger.Fatal(err)
	}
}

func (b Build) tools() error {
	if err := buildTools("devtools", "out/bin/devtools", "cmd/devtools"); err != nil {
		return err
	}
	return buildTools("opstools", "out/bin/opstools", "cmd/opstools")
}

func buildTools(tools, binDir, sourceDir string) error {
	// cross compile so tools can be copied to other machines easily
	archs := []string{"amd64", "386", "arm"} // yes arm, AWS is now supporting arm processors and they are cheap!
	oses := []string{"linux", "darwin", "windows"}
	blacklist := map[string]bool{ // incompatible combinations
		"darwin:arm": true,
	}

	applyBuildEnv := func(apply func(arch, opsys, binPath string) error) error {
		for _, arch := range archs {
			for _, opsys := range oses {
				if blacklist[opsys+":"+arch] {
					continue
				}

				if err := apply(arch, opsys, filepath.Join(binDir, opsys, arch)); err != nil {
					return err
				}
			}
		}

		return nil
	}

	// create the dirs
	err := applyBuildEnv(func(arch, opsys, binPath string) error {
		if err := os.MkdirAll(binPath, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory: %v", binPath, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	logger.Infof("build:%s using %s for %s on %s",
		tools, runtime.Version(), strings.Join(oses, ","), strings.Join(archs, ","))

	// compile each app
	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || filepath.Base(path) != "main.go" {
			return nil
		}

		return applyBuildEnv(func(arch, opsys, binPath string) error {
			app := filepath.Dir(path)
			logger.Debugf("build:%s compiling %s for %s on %s to %s",
				tools, filepath.Base(app), opsys, arch, binPath)

			if err = sh.RunWith(map[string]string{"GOARCH": arch, "GOOS": opsys},
				"go", "build", "-ldflags", "-s -w", "-o", binPath, "./"+app); err != nil {
				return fmt.Errorf("go build %s failed: %v", path, err)
			}

			return nil
		})
	})
}

func buildPackage(pkg string) error {
	targetDir := filepath.Join("out", "bin", pkg)
	binary := filepath.Join(targetDir, "main")
	oldInfo, statErr := os.Stat(binary)
	oldHash, hashErr := fileMD5(binary)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory: %v", targetDir, err)
	}
	if err := sh.RunWith(buildEnv, "go", "build", "-ldflags", "-s -w", "-o", targetDir, "./"+pkg); err != nil {
		return fmt.Errorf("go build %s failed: %v", binary, err)
	}

	if statErr == nil && hashErr == nil {
		if hash, err := fileMD5(binary); err == nil && hash == oldHash {
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

// Generate CloudFormation templates in out/deployments folder
func (b Build) Cfn() {
	if err := b.cfn(); err != nil {
		logger.Fatal(err)
	}
}

func (b Build) cfn() error {
	if err := embedAPISpec(); err != nil {
		return err
	}

	if err := generateGlueTables(); err != nil {
		return err
	}

	settings, err := config.Settings()
	if err != nil {
		return err
	}

	if err := generateAlarms(settings); err != nil {
		return err
	}
	if err := generateDashboards(); err != nil {
		return err
	}
	if err := generateMetrics(); err != nil {
		return err
	}

	return nil
}
