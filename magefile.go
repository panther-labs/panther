// +build mage

package main

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
	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/clean"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/doc"
	"github.com/panther-labs/panther/tools/mage/fmt"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/master"
	"github.com/panther-labs/panther/tools/mage/setup"
	"github.com/panther-labs/panther/tools/mage/teardown"
	"github.com/panther-labs/panther/tools/mage/test"
)

var mageLogger = logger.Get()

// Each exported function and its comment becomes a mage target

type Build mg.Namespace

// Generate API source files
func (Build) API() {
	build.API()
}

// Generate CloudFormation templates in out/deployments
func (Build) Cfn() {
	if err := build.Cfn(); err != nil {
		mageLogger.Fatal(err)
	}
}

// Compile Go Lambda function source
func (Build) Lambda() {
	if err := build.Lambda(); err != nil {
		mageLogger.Fatal(err)
	}
}

// Compile devtools and opstools
func (Build) Tools() {
	if err := build.Tools(); err != nil {
		mageLogger.Fatal(err)
	}
}

// Remove dev libraries and build/test artifacts
func Clean() {
	clean.Clean()
}

// NOTE: Mage ignores the first word of the comment if it matches the function name

// Deploy Deploy Panther to your AWS account
func Deploy() {
	deploy.Deploy()
}

// Preview auto-generated documentation in out/doc
func Doc() {
	doc.Doc()
}

// Format source files
func Fmt() {
	fmt.Fmt()
}

type Master mg.Namespace

// Deploy Deploy single master template (deployments/master.yml) nesting all other stacks
func (Master) Deploy() {
	master.Deploy()
}

// Publish Publish a new Panther release (Panther team only)
func (Master) Publish() {
	master.Publish()
}

// Install build and development dependencies
func Setup() {
	setup.Setup()
}

// Destroy Panther infrastructure
func Teardown() {
	teardown.Teardown()
}

type Test mg.Namespace

// Lint CloudFormation and Terraform templates
func (Test) Cfn() {
	test.Cfn()
}

// Run all required checks for a pull request
func (Test) CI() {
	test.CI()
}

// Test and lint Go source
func (Test) Go() {
	test.Go()
}

// Run integration tests against a live deployment
func (Test) Integration() {
	test.Integration()
}

// Test and lint Python source
func (Test) Python() {
	test.Python()
}

// Test and lint web source
func (Test) Web() {
	test.Web()
}
