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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSwaggerPattern(t *testing.T) {
	assert.False(t, swaggerPattern.MatchString(""))
	assert.False(t, swaggerPattern.MatchString("DefinitionBody: myfile.json"))
	assert.False(t, swaggerPattern.MatchString("DefinitionBody: \napi.yml"))

	assert.True(t, swaggerPattern.MatchString("DefinitionBody:api.yml"))
	assert.True(t, swaggerPattern.MatchString("DefinitionBody: api/compliance.yml  "))
	assert.True(t, swaggerPattern.MatchString("DefinitionBody: api/compliance.yml # trailing comment"))

	// Ensure spaces and comments are consumed
	replaced := swaggerPattern.ReplaceAllString("DefinitionBody: api/compliance.yml # trailing comment", "X")
	assert.Equal(t, replaced, "X")
}

func TestEmbedAPIs(t *testing.T) {
	fmt.Println("")
}
