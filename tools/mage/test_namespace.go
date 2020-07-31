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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/cfnparse"
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

type testTask struct {
	Name string
	Task func() error
}

// CI Run all required checks for a pull request
func (Test) CI() {
	// Formatting modifies files (and may generate new ones), so we need to run this first
	fmtErr := testFmtAndGeneratedFiles()

	// Go unit tests and linting already run in multiple processors
	goUnitErr := testGoUnit()
	goLintErr := testGoLint()

	runTests([]testTask{
		{"fmt", func() error { return fmtErr }},

		// mage test:go
		{"go unit tests", func() error { return goUnitErr }},
		{"golangci-lint", func() error { return goLintErr }},

		// mage test:cfn
		{"build:cfn", build.cfn},
		{"cfn-lint", testCfnLint},
		{"terraform validate", testTfValidate},

		// mage test:doc

		// mage test:python
		{"python unit tests", testPythonUnit},
		{"pylint", testPythonLint},
		{"bandit (python security linting)", testPythonBandit},
		{"mypy (python type checking)", testPythonMypy},

		// mage test:web
		{"npm run eslint", testWebEslint},
		{"npm run tsc", testWebTsc},
		{"npm run test", testWebIntegration},
	})
}

func runTests(tasks []testTask) {
	results := make(chan goroutineResult)

	done := make(chan struct{})
	go func() {
		defer close(done)
		logResults(results, "test:ci", 1, len(tasks), len(tasks))
	}()

	for _, task := range tasks {
		runTask(results, task.Name, task.Task)
	}
	<-done
}

// Lint CloudFormation and Terraform templates
func (Test) Cfn() {
	runTests([]testTask{
		{"build:cfn", build.cfn},
		{"cfn-lint", testCfnLint},
		{"terraform validate", testTfValidate},
	})
}

// Verify links and assets in documentation
func (Test) Doc() {
	// TODO - separate files for "test_doc", "test_python", "test_go", etc

	docFiles := make(map[string]struct{})
	walk(filepath.Join("docs", "gitbook"), func(path string, info os.FileInfo) {
		if filepath.Ext(path) == ".md" {
			docFiles[path] = struct{}{}
		}
	})

	logger.Infof("test:doc: scanning %d documentation .md files", len(docFiles))
	// note: we need the non-greedy variant, hence ".*?"
	linkPattern := regexp.MustCompile(`\[.*?\]\((.*?)\)`) // e.g. "[myfile](path/to/doc.md)"

	// Every link target must be one of the following:

	// web reference - http(s) links
	webRef := regexp.MustCompile(`^https?://[A-Za-z0-9.#?&%/:=_-]{5,}$`)

	// email link - based on the same regex we use for emails in CloudFormation parameters
	emailRef := regexp.MustCompile(`^mailto:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

	// Asset reference - an image in the docs/gitbook/.gitbook/assets folder
	// For example, "../.gitbook/assets/log-analysis/setup-sns1.png"
	assetRef := regexp.MustCompile(`^(?:\.\./)*\.gitbook/assets/[a-z0-9/-]+\.(?:png|jpg)$`)

	// Document reference - link to another documentation page, potentially with a header.
	// For safety and consistency, we don't allow linking to directories, only specific files.
	//
	// Examples:
	//    - "#aws-credentials"                       (header in same file)
	//    - "../enterprise/data-analytics/README.md" (a different document)
	//    - "development.md#deploying"               (header in another file)
	//    - ""                                       (file and header are both optional)
	//
	// Non-examples:
	//    - "../log-analysis"           (can't link to directories - link will fail without README)
	//    - "quick_start.md"            (use "-" instead of "_")
	//    - "quick-start.md#Onboarding" (headers must be lowercase with dashes only)
	docRef := regexp.MustCompile(`^([A-Za-z0-9./-]+\.md)?(#[a-z0-9-]+)?$`)

	for path := range docFiles {
		for _, match := range linkPattern.FindAllSubmatch(readFile(path), -1) {
			// match[0] is entire "[text](target)", match[1] is just "target"
			target := match[1]

			if webRef.Match(target) || emailRef.Match(target) {
				logger.Debugf("test:doc: %s valid web/email link: %s", path, string(target))
				continue
			}

			if assetRef.Match(target) {
				// TODO - validate image path
				logger.Debugf("test:doc: %s image ref: %s", path, string(target))
			} else if docRef.Match(target) {
				// TODO - validate document path
				// TODO - validate header
				logger.Debugf("test:doc: %s doc ref: %s", path, string(target))
			} else {
				logger.Errorf("test:doc: %s: unknown link: %s", path, string(match[0]))
			}
		}
	}
}

// Test and lint Golang source code
func (Test) Go() {
	if err := testGoUnit(); err != nil {
		logger.Fatalf("go unit tests failed: %v", err)
	}

	if err := testGoLint(); err != nil {
		logger.Fatalf("go linting failed: %v", err)
	}
}

// Test and lint Python source code
func (Test) Python() {
	runTests([]testTask{
		{"python unit tests", testPythonUnit},
		{"pylint", testPythonLint},
		{"bandit (python security linting)", testPythonBandit},
		{"mypy (python type checking)", testPythonMypy},
	})
}

// Test and lint web source
func (Test) Web() {
	runTests([]testTask{
		{"npm run eslint", testWebEslint},
		{"npm run tsc", testWebTsc},
		{"npm run test", testWebIntegration},
	})
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

	// cfn-lint will complain:
	//   E3012 Property Resources/SnapshotDLQ/Properties/MessageRetentionPeriod should be of type Integer
	//
	// But if we keep them integers, yaml marshaling converts large integers to scientific notation,
	// which CFN does not understand. So we force string values to serialize them correctly.
	args := []string{"-x", "E3012:strict=false", "--"}
	args = append(args, templates...)
	if err := sh.RunV(pythonLibPath("cfn-lint"), args...); err != nil {
		return err
	}

	// Panther-specific linting for main stacks
	//
	// - Required custom resources
	// - No default parameter values
	var errs []string
	for _, template := range templates {
		if template == "deployments/master.yml" || strings.HasPrefix(template, "deployments/auxiliary") {
			continue
		}

		body, err := cfnparse.ParseTemplate(pythonVirtualEnvPath, template)
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to parse %s: %v", template, err))
			continue
		}

		// Parameter defaults should not be defined in the nested stacks. Defaults are defined in:
		//   - the config file, when deploying from source
		//   - the master template, for pre-packaged deployments
		//
		// Allowing defaults in nested stacks is confusing and leads to bugs where a parameter is
		// defined but never passed through during deployment.
		if err = cfnDefaultParameters(body); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", template, err))
		}

		if template == bootstrapTemplate {
			// Custom resources can't be in the bootstrap stack
			for logicalID, resource := range body["Resources"].(map[string]interface{}) {
				t := resource.(map[string]interface{})["Type"].(string)
				if strings.HasPrefix(t, "Custom::") {
					return fmt.Errorf("%s: %s: custom resources will not work in this stack - use bootstrap-gateway instead",
						template, logicalID)
				}
			}

			// Skip remaining checks
			continue
		}

		// Map logicalID => resource type
		resources := make(map[string]string)
		for logicalID, resource := range body["Resources"].(map[string]interface{}) {
			resources[logicalID] = resource.(map[string]interface{})["Type"].(string)
		}

		// Right now, we just check logicalID and type, but we can always add additional validation
		// of the resource properties in the future if needed.
		for logicalID, resourceType := range resources {
			var err error
			switch resourceType {
			case "AWS::DynamoDB::Table":
				if resources[logicalID+"Alarms"] != "Custom::DynamoDBAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::Serverless::Api":
				if resources[logicalID+"Alarms"] != "Custom::ApiGatewayAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::Serverless::Function":
				err = cfnTestFunction(logicalID, template, resources)
			case "AWS::SNS::Topic":
				if resources[logicalID+"Alarms"] != "Custom::SNSAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::SQS::Queue":
				if resources[logicalID+"Alarms"] != "Custom::SQSAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			case "AWS::StepFunctions::StateMachine":
				if resources[logicalID+"Alarms"] != "Custom::StateMachineAlarms" {
					err = fmt.Errorf("%s needs an associated %s resource in %s",
						logicalID, logicalID+"Alarms", template)
				}
			}

			if err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// Returns an error if there is a parameter with a default value.
func cfnDefaultParameters(template map[string]interface{}) error {
	params, ok := template["Parameters"].(map[string]interface{})
	if !ok {
		return nil
	}

	for name, options := range params {
		if _, exists := options.(map[string]interface{})["Default"]; exists {
			return fmt.Errorf("parameter '%s' should not have a default value. "+
				"Either pass the value from the config file and master stack or use a Mapping", name)
		}
	}

	return nil
}

// Returns an error if an AWS::Serverless::Function is missing associated resources
func cfnTestFunction(logicalID, template string, resources map[string]string) error {
	idPrefix := strings.TrimSuffix(logicalID, "Function")
	if resources[idPrefix+"MetricFilters"] != "Custom::LambdaMetricFilters" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"MetricFilters", template)
	}

	if resources[idPrefix+"Alarms"] != "Custom::LambdaAlarms" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"Alarms", template)
	}

	// Backwards compatibility - these resources did not originally match the naming scheme,
	// renaming the logical IDs would delete + recreate the log group, which usually causes
	// deployments to fail because it tries to create a log group which already exists.
	if template == logAnalysisTemplate {
		switch idPrefix {
		case "AlertsForwarder":
			idPrefix = "AlertForwarder"
		case "Updater":
			idPrefix = "UpdaterFunction"
		}
	}

	if resources[idPrefix+"LogGroup"] != "AWS::Logs::LogGroup" {
		return fmt.Errorf("%s needs an associated %s resource in %s",
			logicalID, idPrefix+"LogGroup", template)
	}

	return nil
}

func testGoUnit() error {
	logger.Info("test:ci: running go unit tests")
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
	return runGoTest("test", "-race", "-p", strconv.Itoa(maxWorkers), "-vet", "", "-cover", "./...")
}

func testGoLint() error {
	logger.Info("test:ci: running go metalinter")
	args := []string{"run", "--timeout", "10m", "-j", strconv.Itoa(maxWorkers)}
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
		if err := runWithoutStderr(pythonLibPath("python3"), append(args, target)...); err != nil {
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
	return runWithoutStderr(pythonLibPath("bandit"), append(args, pyTargets...)...)
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

func testWebIntegration() error {
	return sh.Run("npm", "run", "test")
}

func testTfValidate() error {
	root := filepath.Join("deployments", "auxiliary", "terraform")
	paths, err := ioutil.ReadDir(root)
	if err != nil {
		return fmt.Errorf("failed to list tf templates: %v", err)
	}

	// Terraform validate needs a valid AWS region to "configure" the provider.
	// No AWS calls are actually necessary; this can be any region.
	env := map[string]string{"AWS_REGION": "us-east-1"}

	for _, info := range paths {
		if !info.IsDir() {
			continue
		}

		dir := filepath.Join(root, info.Name())
		if err := sh.Run(terraformPath, "init", "-backend=false", "-input=false", dir); err != nil {
			return fmt.Errorf("tf init %s failed: %v", dir, err)
		}

		if err := sh.RunWith(env, terraformPath, "validate", dir); err != nil {
			return fmt.Errorf("tf validate %s failed: %v", dir, err)
		}
	}

	return nil
}

// Integration Run integration tests (integration_test.go,integration.py)
func (t Test) Integration() {
	getSession()

	logger.Warnf("Integration tests will erase all Panther data in account %s (%s)",
		getAccountID(), *awsSession.Config.Region)
	result := promptUser("Are you sure you want to continue? (yes|no) ", nonemptyValidator)
	if strings.ToLower(result) != "yes" {
		logger.Fatal("integration tests aborted")
	}

	mg.Deps(build.API)

	if pkg := os.Getenv("PKG"); pkg != "" {
		// One specific package requested: run integration tests just for that
		if err := goPkgIntegrationTest(pkg); err != nil {
			logger.Fatal(err)
		}
		return
	}

	errCount := 0
	walk(".", func(path string, info os.FileInfo) {
		if filepath.Base(path) == "integration_test.go" {
			if err := goPkgIntegrationTest("./" + filepath.Dir(path)); err != nil {
				logger.Error(err)
				errCount++
			}
		}
	})

	logger.Info("test:integration: python policy engine")
	if err := sh.RunV(pythonLibPath("python3"), "internal/compliance/policy_engine/tests/integration.py"); err != nil {
		logger.Errorf("python integration test failed: %v", err)
		errCount++
	}

	if errCount > 0 {
		logger.Fatalf("%d integration test(s) failed", errCount)
	}
}

// Run integration tests for a single Go package.
func goPkgIntegrationTest(pkg string) error {
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

	return sh.RunV("go", args...)
}
