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
	"github.com/panther-labs/panther/tools/mage/clean"
	"github.com/panther-labs/panther/tools/mage/fmt"
	"github.com/panther-labs/panther/tools/mage/setup"
)

// Each exported function and its comment becomes a mage target

// Remove dev libraries and build/test artifacts
func Clean() {
	clean.Clean()
}

// Format source files
func Fmt() {
	fmt.Fmt()
}

// Install all build and development dependencies
func Setup() {
	setup.Setup()
}
