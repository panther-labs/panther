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

	"github.com/stretchr/testify/assert"
)

// Writing this as a real "test" (instead of in mage directly) makes it easier to add assertions.
// This also avoids bloating mage with all of the compiled testing code.
func TestIntegrationEndToEnd(t *testing.T) {
	if strings.ToLower(os.Getenv("INTEGRATION_TEST")) != "true" {
		t.Skip()
	}

	assert.Equal(t, true, false)
}
