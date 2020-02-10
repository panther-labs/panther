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

	"github.com/aws/aws-sdk-go/service/sts"
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

// Cfn Lint CloudFormation templates
func (t Test) Cfn() {
	if testCfn() {
		logger.Info("test:cfn: PASS")
	} else {
		logger.Fatal("test:cfn: FAIL")
	}
}

func testCfn() bool {
	var templates []string
	walk("deployments", func(path string, info os.FileInfo) {
		if !info.IsDir() && filepath.Ext(path) == ".yml" && filepath.Base(path) != "panther_config.yml" {
			templates = append(templates, path)
		}
	})
	pass := true

	// cfn-lint
	logger.Infof("test:cfn: cfn-lint %d templates", len(templates))
	if err := sh.RunV(pythonLibPath("cfn-lint"), templates...); err != nil {
		logger.Errorf("cfn-lint failed: %v", err)
		pass = false
	}

	// formatting
	logger.Infof("test:cfn: formatting")
	if err := sh.RunV(nodePath("prettier"), "--list-different", "deployments/**.yml"); err != nil {
		logger.Errorf("prettier diff: %v", err)
		pass = false
	}

	return pass
}

// Go Test Go source
func (t Test) Go() {
	if testGo() {
		logger.Info("test:go: PASS")
	} else {
		logger.Fatal("test:go: FAIL")
	}
}

func testGo() bool {
	pass := true

	// unit tests
	logger.Info("test:go: unit tests")
	args := []string{"test", "-vet", "", "-cover", "./..."}
	var err error
	if mg.Verbose() {
		// verbose mode - show "go test" output (all package names)
		err = sh.Run("go", args...)
	} else {
		// standard mode - filter output to show only the errors
		var output string
		output, err = sh.Output("go", args...)
		if err != nil {
			for _, line := range strings.Split(output, "\n") {
				if !strings.HasPrefix(line, "ok  	github.com/panther-labs/panther") &&
					!strings.HasPrefix(line, "?   	github.com/panther-labs/panther") {

					fmt.Println(line)
				}
			}
		}
	}

	if err != nil {
		logger.Errorf("go unit tests failed: %v", err)
		pass = false
	}

	// metalinting
	logger.Info("test:go: golangci-lint")
	args = []string{"run", "--timeout", "10m"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	if err := sh.RunV(filepath.Join(setupDirectory, "golangci-lint"), args...); err != nil {
		logger.Errorf("go linting failed: %v", err)
		pass = false
	}

	return pass
}

// Python Test Python source
func (t Test) Python() {
	if testPython() {
		logger.Info("test:python: PASS")
	} else {
		logger.Fatal("test:python: FAIL")
	}
}

func testPython() bool {
	pass := true

	args := []string{"-m", "unittest", "discover"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	} else {
		args = append(args, "--quiet")
	}

	logger.Info("test:python: unit tests")
	for _, target := range []string{"internal/core", "internal/compliance", "internal/log_analysis"} {
		if err := sh.RunV(pythonLibPath("python3"), append(args, target)...); err != nil {
			logger.Errorf("python unit tests failed: %v", err)
			pass = false
		}
	}

	// python bandit (security linting)
	logger.Info("test:python: bandit security linting")
	args = []string{"--recursive"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	} else {
		args = append(args, "--quiet")
	}
	if err := sh.Run(pythonLibPath("bandit"), append(args, pyTargets...)...); err != nil {
		logger.Errorf("python security linting failed: %v", err)
		pass = false
	}

	// python lint - runs twice (once for src directories, once for test directories)
	logger.Info("test:python: pylint")
	args = []string{"-j", "0", "--max-line-length", "140", "--score", "no"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	// pylint src
	srcArgs := append(args, "--ignore", "tests", "--disable", strings.Join(pylintSrcDisabled, ","))
	if err := sh.RunV(pythonLibPath("pylint"), append(srcArgs, pyTargets...)...); err != nil {
		logger.Errorf("pylint source failed: %v", err)
		pass = false
	}
	// pylint tests
	testArgs := append(args, "--ignore", "src", "--disable", strings.Join(pylintTestsDisabled, ","))
	if err := sh.RunV(pythonLibPath("pylint"), append(testArgs, pyTargets...)...); err != nil {
		logger.Errorf("pylint tests failed: %v", err)
		pass = false
	}

	// python mypy (type check)
	logger.Info("test:python: mypy type-checking")
	args = []string{"--cache-dir", "out/.mypy_cache", "--no-error-summary",
		"--disallow-untyped-defs", "--ignore-missing-imports", "--warn-unused-ignores"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	if err := sh.RunV(pythonLibPath("mypy"), append(args, pyTargets...)...); err != nil {
		logger.Errorf("mypy failed: %v", err)
		pass = false
	}

	// python formatting
	logger.Info("test:python: yapf formatting")
	args = []string{"--diff", "--parallel", "--recursive"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	if output, err := sh.Output(pythonLibPath("yapf"), append(args, pyTargets...)...); err != nil {
		logger.Errorf("yapf diff: %d bytes (err: %v)", len(output), err)
		pass = false
	}

	return pass
}

// Web Test web source
func (t Test) Web() {
	if testWeb() {
		logger.Info("test:web: PASS")
	} else {
		logger.Fatal("test:web: FAIL")
	}
}

func testWeb() bool {
	pass := true

	if _, err := os.Stat("node_modules"); err != nil {
		logger.Errorf("npm not initialized (%v): run 'mage setup:web'", err)
		return false
	}

	logger.Info("test:web: npm run lint")
	if err := sh.RunV("npm", "run", "lint"); err != nil {
		logger.Errorf("npm lint failed: %v", err)
		pass = false
	}

	logger.Info("test:web: npm audit")
	if err := sh.RunV("npm", "audit"); err != nil {
		logger.Errorf("npm audit failed: %v", err)
		pass = false
	}

	return pass
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
func (t Test) CI() {
	var failed []string
	if !testCfn() {
		failed = append(failed, "cfn")
	}
	if !testGo() {
		failed = append(failed, "go")
	}
	if !testPython() {
		failed = append(failed, "python")
	}
	if !testWeb() {
		failed = append(failed, "web")
	}

	if len(failed) == 0 {
		logger.Info("test:ci: PASS")
	} else {
		logger.Fatal("test:ci: FAIL: " + strings.Join(failed, ","))
	}
}

// Integration Run integration tests (integration_test.go,integration.py)
func (t Test) Integration() {
	// Check the AWS account ID
	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}
	identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		logger.Fatalf("failed to get caller identity: %v", err)
	}

	logger.Warnf("INTEGRATION TESTS WILL ERASE ALL PANTHER DATA IN AWS ACCOUNT %s", *identity.Account)
	result := promptUser("Are you sure you want to continue? (yes|no) ", nonemptyValidator)
	if strings.ToLower(result) != "yes" {
		logger.Fatal("permission denied: integration tests canceled")
	}

	mg.Deps(build.API)

	if pkg := os.Getenv("PKG"); pkg != "" {
		// One specific package requested: run integration tests just for that
		goPkgIntegrationTest(pkg)
		return
	}

	walk("internal", func(path string, info os.FileInfo) {
		if filepath.Base(path) == "integration_test.go" {
			goPkgIntegrationTest("./" + filepath.Dir(path))
		}
	})

	logger.Info("test:integration: python policy engine")
	if err := sh.RunV(pythonLibPath("python3"), "internal/compliance/policy_engine/tests/integration.py"); err != nil {
		logger.Fatalf("python integration test failed: %v", err)
	}
}

// Run integration tests for a single Go package.
func goPkgIntegrationTest(pkg string) {
	if err := os.Setenv("INTEGRATION_TEST", "True"); err != nil {
		logger.Fatalf("failed to set INTEGRATION_TEST environment variable: %v", err)
	}
	defer os.Unsetenv("INTEGRATION_TEST")

	logger.Info("test:integration: go test " + pkg + " -run=TestIntegration*")
	// -count 1 is the idiomatic way to disable test caching
	args := []string{"test", pkg, "-run=TestIntegration*", "-p", "1", "-count", "1"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	if err := sh.RunV("go", args...); err != nil {
		logger.Fatalf("go test %s failed: %v", pkg, err)
	}
}
