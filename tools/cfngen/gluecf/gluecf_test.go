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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/awsglue"
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
	expectedOutput, err := readTestFile("testdata/gluecf.json.cf")
	require.NoError(t, err)

	// use simple consistent reference set of parsers
	table, err := awsglue.NewGlueMetadata(awsglue.TablesDatabaseName, "dummy", "dummy",
		awsglue.GlueTableHourly, false, &dummyParserEvent{})
	require.NoError(t, err)
	tables := []*awsglue.GlueMetadata{table}

	cf, err := GenerateCloudFormation(tables)
	require.NoError(t, err)

	// un-comment to see output
	// os.Stdout.Write(cf)

	assert.Equal(t, expectedOutput, string(cf))
}
