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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Test contains targets for testing code syntax, style, and correctness.
type Test mg.Namespace

var (
	build             = Build{}
	pylintSrcDisabled = []string{
		"duplicate-code",
		"fixme",
		"missing-module-docstring",
		"too-few-public-methods",
	}
	pylintTestsDisabled = append(pylintSrcDisabled,
		"missing-class-docstring",
		"missing-function-docstring",
		"no-self-use",
		"protected-access",
	)
)

// JoinErrors formats multiple errors into a single error.
func JoinErrors(command string, errList []error) error {
	if len(errList) == 0 {
		return nil
	}

	errString := fmt.Sprintf("%s failed with %d error(s):", command, len(errList))
	for i, err := range errList {
		errString += fmt.Sprintf("\n\t[%d] %s", i+1, err)
	}
	return errors.New(errString)
}

// Lint Check code style
func (t Test) Lint() error {
	mg.Deps(build.API)
	var errs []error

	// go metalinting
	fmt.Println("test:lint: golang")
	args := []string{"run", "--timeout", "10m"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	if err := sh.RunV("golangci-lint", args...); err != nil {
		errs = append(errs, err)
	}

	// python bandit (security linting)
	fmt.Println("test:lint: python security")
	args = []string{"--recursive"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	} else {
		args = append(args, "--quiet")
	}
	if err := sh.Run(pythonLibPath("bandit"), append(args, pyTargets...)...); err != nil {
		errs = append(errs, err)
	}

	// python yapf
	fmt.Println("test:lint: python")
	args = []string{"--diff", "--parallel", "--recursive"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	if output, err := sh.Output(pythonLibPath("yapf"), append(args, pyTargets...)...); err != nil {
		errs = append(errs, fmt.Errorf("yapf diff: %d bytes (err: %v)", len(output), err))
	}

	// python lint - runs twice (once for src directories, once for test directories)
	args = []string{"-j", "0", "--max-line-length", "140", "--score", "no"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	// pylint src
	srcArgs := append(args, "--ignore", "tests", "--disable", strings.Join(pylintSrcDisabled, ","))
	if err := sh.RunV(pythonLibPath("pylint"), append(srcArgs, pyTargets...)...); err != nil {
		errs = append(errs, err)
	}
	// pylint tests
	testArgs := append(args, "--ignore", "src", "--disable", strings.Join(pylintTestsDisabled, ","))
	if err := sh.RunV(pythonLibPath("pylint"), append(testArgs, pyTargets...)...); err != nil {
		errs = append(errs, err)
	}

	// python mypy (type check)
	args = []string{"--cache-dir", "out/.mypy_cache", "--no-error-summary",
		"--disallow-untyped-defs", "--ignore-missing-imports", "--warn-unused-ignores"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	if err := sh.RunV(pythonLibPath("mypy"), append(args, pyTargets...)...); err != nil {
		errs = append(errs, err)
	}

	// Lint CloudFormation
	fmt.Println("test:lint: CloudFormation")
	var templates []string
	err := filepath.Walk("deployments", func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, "config.yml") {
			templates = append(templates, path)
		}
		return err
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("filepath.Walk(deployments) failed: %v", err))
	}
	if err := sh.RunV(pythonLibPath("cfn-lint"), templates...); err != nil {
		errs = append(errs, err)
	}

	return JoinErrors("test:lint", errs)
}

// Unit Run unit tests
func (Test) Unit() error {
	mg.Deps(build.API)
	args := []string{"test", "-cover", "./..."}
	if mg.Verbose() {
		args = append(args, "-v")
	}

	fmt.Println("test:unit: go test")
	if err := sh.RunV("go", args...); err != nil {
		return err
	}

	args = []string{"-m", "unittest", "discover"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	} else {
		args = append(args, "--quiet")
	}

	for _, target := range []string{"internal/core", "internal/compliance", "internal/log_analysis"} {
		fmt.Println("test:unit python unittest", target)
		if err := sh.RunV(pythonLibPath("python3"), append(args, target)...); err != nil {
			return err
		}
	}

	return nil
}

// Cover Run Go unit tests and view test coverage in HTML
func (t Test) Cover() error {
	mg.Deps(build.API)
	if err := os.MkdirAll("out/", 0755); err != nil {
		return err
	}

	if err := sh.RunV("go", "test", "-cover", "-coverprofile=out/.coverage", "./..."); err != nil {
		return err
	}

	return sh.Run("go", "tool", "cover", "-html=out/.coverage")
}

// CI Run all required checks
func (t Test) CI() error {
	if err := build.Lambda(); err != nil {
		return err
	}
	if err := t.Unit(); err != nil {
		return err
	}
	return t.Lint()
}

// Integration Run TestIntegration* for PKG (default: ./...)
func (t Test) Integration() error {
	mg.Deps(build.API)
	if err := sh.Run("go", "clean", "-testcache"); err != nil {
		return err
	}

	pkg := os.Getenv("PKG")
	if pkg == "" {
		pkg = "./..."
	}
	// Note: We do NOT run integration tests in parallel
	testArgs := []string{"test", pkg, "-run=TestIntegration*", "-p", "1"}
	if mg.Verbose() {
		testArgs = append(testArgs, "-v")
	} else {
		fmt.Println("test:integration: go test " + pkg + " -run=TestIntegration*")
	}

	if err := os.Setenv("INTEGRATION_TEST", "True"); err != nil {
		return err
	}
	defer os.Unsetenv("INTEGRATION_TEST")
	if err := sh.RunV("go", testArgs...); err != nil {
		return err
	}

	// Run Python integration tests unless a Go pkg is specified
	if os.Getenv("PKG") == "" {
		fmt.Println("test:integration: python engine")
		return sh.RunV(pythonLibPath("python3"), "internal/compliance/policy_engine/tests/integration.py")
	}
	return nil
}
