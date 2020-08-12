package mage

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Test and lint Golang source code
func (Test) Go() {
	if err := testGoUnit(); err != nil {
		logger.Fatalf("go unit tests failed: %v", err)
	}

	if err := testGoLint(); err != nil {
		logger.Fatalf("go linting failed: %v", err)
	}
}

func testGoUnit() error {
	logger.Info("test:go: running go unit tests")
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
	logger.Info("test:go: running go metalinter")
	args := []string{"run", "--timeout", "10m", "-j", strconv.Itoa(maxWorkers)}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	return sh.RunV(filepath.Join(setupDirectory, "golangci-lint"), args...)
}
