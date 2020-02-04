package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFixTemplateURL(t *testing.T) {
	// Basic example
	originalTemplate := "TemplateURL: https://s3.region.amazonaws.com/bucket/panther-app/1.template"
	expectedTemplate := "TemplateURL: https://s3.amazonaws.com/bucket/panther-app/1.template"
	assert.Equal(t, expectedTemplate, fixPackageTemplateURL(originalTemplate))

	// Maintains leading whitespace
	originalTemplate = "   TemplateURL: https://s3.region.amazonaws.com/bucket/panther-app/1.template"
	expectedTemplate = "   TemplateURL: https://s3.amazonaws.com/bucket/panther-app/1.template"
	assert.Equal(t, expectedTemplate, fixPackageTemplateURL(originalTemplate))

	// Don't change things that are not TemplateURLs
	originalTemplate = "https://s3.region.amazonaws.com/bucket/panther-app/1.template"
	expectedTemplate = "https://s3.region.amazonaws.com/bucket/panther-app/1.template"
	assert.Equal(t, expectedTemplate, fixPackageTemplateURL(originalTemplate))

	// Don't change things that are not already in global format
	originalTemplate = "https://s3.amazonaws.com/bucket/panther-app/1.template"
	expectedTemplate = "https://s3.amazonaws.com/bucket/panther-app/1.template"
	assert.Equal(t, expectedTemplate, fixPackageTemplateURL(originalTemplate))
}
