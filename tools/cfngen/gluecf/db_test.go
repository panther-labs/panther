package gluecf

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
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/tools/cfngen"
)

func TestDatabase(t *testing.T) {
	expectedFile := "testdata/db.template.json"

	catalogID := "12345"
	dbName := "db1"
	description := "Test db"

	db := NewDatabase(catalogID, dbName, description)

	resources := make(map[string]interface{})

	resources[dbName] = db

	cfTemplate := cfngen.NewTemplate("Test template", nil, resources, nil)

	cf, err := cfTemplate.CloudFormation()
	require.NoError(t, err)

	// uncomment to make a new expected file
	// writeTestFile(cf, expectedFile)

	expectedOutput, err := readTestFile(expectedFile)
	require.NoError(t, err)

	assert.Equal(t, expectedOutput, cf)
}
