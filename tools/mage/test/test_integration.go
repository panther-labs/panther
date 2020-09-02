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
	"github.com/panther-labs/panther/tools/mage/build"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Integration Run integration tests (integration_test.go,integration.py)
func (t Test) Integration() {
	log.Warnf("Integration tests will erase all Panther data in account %s (%s)",
		clients.AccountID(), clients.Region())
	result := prompt.Read("Are you sure you want to continue? (yes|no) ", prompt.NonemptyValidator)
	if strings.ToLower(result) != "yes" {
		log.Fatal("integration tests aborted")
	}

	mg.Deps(build.build.API)

	if pkg := os.Getenv("PKG"); pkg != "" {
		// One specific package requested: run integration tests just for that
		if err := goPkgIntegrationTest("test:integration", pkg, mg.Verbose(), nil); err != nil {
			log.Fatal(err)
		}
		return
	}

	errCount := 0
	util.Walk(".", func(path string, info os.FileInfo) {
		// This intentionally does not include the end-to-end test (e2e_test.go)
		if filepath.Base(path) == "integration_test.go" {
			if err := goPkgIntegrationTest("test:integration", "./"+filepath.Dir(path), mg.Verbose(), nil); err != nil {
				log.Error(err)
				errCount++
			}
		}
	})

	log.Info("test:integration: python policy engine")
	if err := sh.RunV(util.PythonLibPath("python3"), "internal/compliance/policy_engine/tests/integration.py"); err != nil {
		log.Errorf("python integration test failed: %v", err)
		errCount++
	}

	if errCount > 0 {
		log.Fatalf("%d integration test(s) failed", errCount)
	}
}

// Run integration tests for a single Go package.
func goPkgIntegrationTest(mageCmd, pkg string, verbose bool, env map[string]string) error {
	// -count 1 is the idiomatic way to disable test caching
	// -timeout 0 disables the test timeout
	args := []string{"test", pkg, "-run=TestIntegration*", "-p", "1", "-count", "1", "-timeout", "0"}
	if verbose {
		args = append(args, "-v")
	}

	if env == nil {
		env = make(map[string]string)
	}
	env["INTEGRATION_TEST"] = "True"

	log.Infof("%s: %v go %s", mageCmd, env, strings.Join(args, " "))
	return sh.RunWithV(env, "go", args...)
}
