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
	"github.com/panther-labs/panther/tools/mage/gen"
	"github.com/panther-labs/panther/tools/mage/master"
	"github.com/panther-labs/panther/tools/mage/setup"
	"github.com/panther-labs/panther/tools/mage/srcfmt"
	"github.com/panther-labs/panther/tools/mage/teardown"
	"github.com/panther-labs/panther/tools/mage/test"
)

// Each exported function and its comment becomes a mage target

type Build mg.Namespace

// Compile Go Lambda function source
func (Build) Lambda() error {
	return build.Lambda()
}

// Compile devtools and opstools
func (Build) Tools() error {
	return build.Tools()
}

// Export native schemas as YAML
func (Build) Schemas() error {
	return build.Schemas()
}

// Remove dev libraries and build/test artifacts
func Clean() error {
	return clean.Clean()
}

// NOTE: Mage ignores the first word of the comment if it matches the function name

// Deploy Deploy Panther to your AWS account
func Deploy() error {
	return deploy.Deploy()
}

// Preview auto-generated documentation in out/doc
func Doc() error {
	return doc.Doc()
}

// Format source files
func Fmt() error {
	return srcfmt.Fmt()
}

// Autogenerate API-related source files and CloudWatch dashboards
func Gen() error {
	return gen.Gen()
}

type Master mg.Namespace

// Deploy Deploy single master template nesting all other stacks
func (Master) Deploy() error {
	return master.Deploy()
}

// Publish Publish a new Panther release (Panther team only)
func (Master) Publish() error {
	return master.Publish()
}

// Install development dependencies (not required to deploy)
func Setup() error {
	return setup.Setup()
}

// Destroy Panther infrastructure
func Teardown() error {
	return teardown.Teardown()
}

type Test mg.Namespace

// Lint CloudFormation and Terraform templates
func (Test) Cfn() error {
	return test.Cfn()
}

// Run all required checks for a pull request
func (Test) CI() error {
	return test.CI()
}

// Test and lint Go source
func (Test) Go() error {
	return test.Go()
}

// Run integration tests against a live deployment
func (Test) Integration() error {
	return test.Integration()
}

// Test and lint Python source
func (Test) Python() error {
	return test.Python()
}

// Test and lint web source
func (Test) Web() error {
	return test.Web()
}
