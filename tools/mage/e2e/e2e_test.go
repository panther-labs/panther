// Package e2e provides an end-to-end deployment test, triggered by 'mage test:e2e'
package e2e

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
	"os"
	"strings"
	"testing"

	"github.com/panther-labs/panther/tools/mage/logger"
)

var log = logger.Get()

// NOTE to self - adding this as a separate pkg makes it easier for others to extend it
// To avoid importing from mage directly (which would encourage exporting funcs that could turn into mage targets),
// I've been splitting out parts of mage into other packages.

// Using the testing library (instead of adding to mage directly) makes it easier to add assertions.
// This also avoids bloating mage with all of the compiled testing code.
//
// It's recommended to run this test in a fresh account when possible.
func TestIntegrationEndToEnd(t *testing.T) {
	if strings.ToLower(os.Getenv("INTEGRATION_TEST")) != "true" {
		t.Skip()
	}

	t.Run("PreTeardown", preTeardown)
}

// Teardown all Panther resources in the region to start with a clean slate.
func preTeardown(t *testing.T) {
	// NOTE: AWS does not allow programmatically removing AWSService IAM roles

	// We want timestamps, colors, and levels from the standard mage logger,
	// so we use that instead of t.Log().
	log.Info("***** test:e2e : Stage 1/8 : Pre-Teardown *****")
}
