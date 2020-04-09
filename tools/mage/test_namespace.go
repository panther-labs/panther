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
	"sort"
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

// CI Run all required checks for a pull request
func (t Test) CI() {
	// Formatting modifies files (and may generate new ones), so we need to run this first
	fmtErr := testFmtAndGeneratedFiles()

	results := make(chan goroutineResult)
	count := 0

	logger.Info("running tests in parallel...")
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"fmt", fmtErr}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"build:cfn", build.cfn()}
	}(results)

	// We build tools and lambda source in parallel, but if you run into problems with Go modules,
	// we may have to do all go compilation sequentially.
	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"build:lambda", build.lambda()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"build:tools", build.tools()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"cfn-lint", testCfnLint()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"go unit tests", testGoUnit()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"golangci-lint", testGoLint()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"python unit tests", testPythonUnit()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"pylint", testPythonLint()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"bandit (python security linting)", testPythonBandit()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"mypy (python type checking)", testPythonMypy()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"npm run eslint", testWebEslint()}
	}(results)

	count++
	go func(c chan goroutineResult) {
		c <- goroutineResult{"npm run tsc", testWebTsc()}
	}(results)

	logResults(results, "test:ci", count)
}

// Format source files and build APIs and check for changes.
//
// In CI, this returns an error and fails the test if files were not formatted.
// Locally, we only log a warning if files were not formatted (test:ci will still pass).
func testFmtAndGeneratedFiles() error {
	// Formatting is fairly complex: yapf, gofmt, goimports, prettier, docs, license headers, etc
	// It's easier to just run "fmt" and look for changes than to check diffs from each tool individually
	beforeHashes, err := sourceHashes()
	if err != nil {
		return err
	}

	build.API()
	Fmt()

	afterHashes, err := sourceHashes()
	if err != nil {
		return err
	}

	if diffs := fileDiffs(beforeHashes, afterHashes); len(diffs) > 0 {
		sort.Strings(diffs)
		if runningInCI() {
			logger.Errorf("%d file diffs after build:api + fmt:\n  %s", len(diffs), strings.Join(diffs, "\n  "))
			return fmt.Errorf("%d file diffs after 'mage build:api fmt'", len(diffs))
		}

		logger.Warnf("%d file diffs after build:api + fmt:\n  %s", len(diffs), strings.Join(diffs, "\n  "))
		logger.Warn("remember to commit formatted files or CI will fail")
	}

	return nil
}

func testCfnLint() error {
	var templates []string
	walk("deployments", func(path string, info os.FileInfo) {
		if !info.IsDir() && filepath.Ext(path) == ".yml" && filepath.Base(path) != "panther_config.yml" {
			templates = append(templates, path)
		}
	})

	return sh.RunV(pythonLibPath("cfn-lint"), templates...)
}

func testGoUnit() error {
	runGoTest := func(args ...string) error {
		if mg.Verbose() {
			// verbose mode - show "go test" output (all package names)
			return sh.Run("go", args...)
		}

		// standard mode - filter output to show only the errors
		var output string
		output, err := sh.Output("go", args...)
		if err != nil {
			for _, line := range strings.Split(output, "\n") {
				if !strings.HasPrefix(line, "ok  	github.com/panther-labs/panther") &&
					!strings.HasPrefix(line, "?   	github.com/panther-labs/panther") {

					fmt.Println(line)
				}
			}
		}
		return err
	}

	// unit tests and race detection
	if err := runGoTest("test", "-race", "-vet", "", "-cover", "./..."); err != nil {
		return err
	}

	// One package is explicitly skipped by -race, we have to run its unit tests separately
	return runGoTest("test", "-vet", "", "-cover", "./internal/log_analysis/log_processor/destinations")
}

func testGoLint() error {
	args := []string{"run", "--timeout", "10m"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	return sh.RunV(filepath.Join(setupDirectory, "golangci-lint"), args...)
}

func testPythonUnit() error {
	args := []string{"-m", "unittest", "discover"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	} else {
		args = append(args, "--quiet")
	}

	for _, target := range []string{"internal/core", "internal/compliance", "internal/log_analysis"} {
		if err := sh.Run(pythonLibPath("python3"), append(args, target)...); err != nil {
			return fmt.Errorf("python unit tests failed: %v", err)
		}
	}

	return nil
}

func testPythonLint() error {
	// pylint - runs twice (once for src directories, once for test directories)
	args := []string{"-j", "0", "--max-line-length", "140", "--score", "no"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}

	// pylint src
	srcArgs := append(args, "--ignore", "tests", "--disable", strings.Join(pylintSrcDisabled, ","))
	if err := sh.RunV(pythonLibPath("pylint"), append(srcArgs, pyTargets...)...); err != nil {
		return fmt.Errorf("pylint source failed: %v", err)
	}

	// pylint tests
	testArgs := append(args, "--ignore", "src", "--disable", strings.Join(pylintTestsDisabled, ","))
	if err := sh.RunV(pythonLibPath("pylint"), append(testArgs, pyTargets...)...); err != nil {
		return fmt.Errorf("pylint tests failed: %v", err)
	}

	return nil
}

func testPythonBandit() error {
	args := []string{"--recursive"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	} else {
		args = append(args, "--quiet")
	}
	return sh.Run(pythonLibPath("bandit"), append(args, pyTargets...)...)
}

func testPythonMypy() error {
	args := []string{"--cache-dir", "out/.mypy_cache", "--no-error-summary",
		"--disallow-untyped-defs", "--ignore-missing-imports", "--warn-unused-ignores"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	return sh.RunV(pythonLibPath("mypy"), append(args, pyTargets...)...)
}

func testWebEslint() error {
	return sh.Run("npm", "run", "eslint")
}

func testWebTsc() error {
	return sh.Run("npm", "run", "tsc")
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

	logger.Warnf("Integration tests will erase all Panther data in account %s (%s)",
		*identity.Account, *awsSession.Config.Region)
	result := promptUser("Are you sure you want to continue? (yes|no) ", nonemptyValidator)
	if strings.ToLower(result) != "yes" {
		logger.Fatal("integration tests aborted")
	}

	mg.Deps(build.API)

	if pkg := os.Getenv("PKG"); pkg != "" {
		// One specific package requested: run integration tests just for that
		goPkgIntegrationTest(pkg)
		return
	}

	walk(".", func(path string, info os.FileInfo) {
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
