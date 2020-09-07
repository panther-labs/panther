package test

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
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

var (
	pythonTests = []testTask{
		{"python unit tests", testPythonUnit},
		{"pylint", testPythonLint},
		{"bandit (python security linting)", testPythonBandit},
		{"mypy (python type checking)", testPythonMypy},
	}
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

// Test and lint Python source code
func Python() error {
	log = logger.Build("[test:python]")
	return runTests(pythonTests)
}

func testPythonUnit() error {
	args := []string{"-m", "unittest", "discover"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	} else {
		args = append(args, "--quiet")
	}

	for _, target := range []string{"internal/core", "internal/compliance", "internal/log_analysis"} {
		if err := util.RunWithCapturedOutput(util.PipPath("python3"), append(args, target)...); err != nil {
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
	if err := sh.RunV(util.PipPath("pylint"), append(srcArgs, util.PyTargets...)...); err != nil {
		return fmt.Errorf("pylint source failed: %v", err)
	}

	// pylint tests
	testArgs := append(args, "--ignore", "src", "--disable", strings.Join(pylintTestsDisabled, ","))
	if err := sh.RunV(util.PipPath("pylint"), append(testArgs, util.PyTargets...)...); err != nil {
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
	return util.RunWithCapturedOutput(util.PipPath("bandit"), append(args, util.PyTargets...)...)
}

func testPythonMypy() error {
	args := []string{"--cache-dir", "out/.mypy_cache", "--no-error-summary",
		"--disallow-untyped-defs", "--ignore-missing-imports", "--warn-unused-ignores"}
	if mg.Verbose() {
		args = append(args, "--verbose")
	}
	return sh.RunV(util.PipPath("mypy"), append(args, util.PyTargets...)...)
}
