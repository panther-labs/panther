package mage

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/pkg/prompt"
)

// Integration Run integration tests (integration_test.go,integration.py)
func (t Test) Integration() {
	getSession()

	logger.Warnf("Integration tests will erase all Panther data in account %s (%s)",
		getAccountID(), *awsSession.Config.Region)
	result := prompt.Read("Are you sure you want to continue? (yes|no) ", prompt.NonemptyValidator)
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
