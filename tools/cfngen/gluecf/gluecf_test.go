package gluecf

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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type dummyParserEvent struct {
	commonFields                       // inherit these fields via composition
	DOB          timestamp.RFC3339     `description:"test field"`
	Anniversary  timestamp.ANSICwithTZ `description:"test field"`
}

type commonFields struct {
	FirstName string `description:"test field"`
	LastName  string `description:"test field"`
}

func TestTablesCloudFormation(t *testing.T) {
	// use simple consistent reference set of parsers
	table := awsglue.NewGlueTableMetadata(models.LogData, "Log.Type", "dummy", awsglue.GlueTableHourly, &dummyParserEvent{})
	tables := []*awsglue.GlueTableMetadata{table}

	cf, err := GenerateTables(tables)
	require.NoError(t, err)

	const expectedFile = "testdata/gluecf.json.cf"
	// uncomment to write new expected file
	// require.NoError(t, ioutil.WriteFile(expectedFile, cf, 0644))

	expected, err := ioutil.ReadFile(expectedFile)
	require.NoError(t, err)
	assert.JSONEq(t, string(expected), string(cf))
}
