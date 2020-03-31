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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/tools/cfngen"
)

func TestTables(t *testing.T) {
	expectedFile := "testdata/tables.template.json"

	// pass in bucket name
	parameters := make(map[string]interface{})
	parameters["Bucket"] = &cfngen.Parameter{
		Type:        "String",
		Description: "Bucket to hold data for table",
	}

	resources := make(map[string]interface{})

	catalogID := "12345"
	dbName := "db1"

	db := NewDatabase(catalogID, dbName, "Test database")

	resources[dbName] = db

	// same for both tables
	columns := []Column{
		{Name: "c1", Type: "int", Comment: "foo"},
		{Name: "c2", Type: "varchar", Comment: "bar"},
	}

	partitionKeys := []Column{
		{Name: "year", Type: "int", Comment: "year"},
		{Name: "month", Type: "int", Comment: "month"},
		{Name: "day", Type: "int", Comment: "day"},
	}

	tableName := "parquetTable"
	description := "Test table"
	location := cfngen.Sub{Sub: "s3//${Bucket}/" + dbName + "/" + tableName}
	table := NewParquetTable(&NewTableInput{
		CatalogID:     catalogID,
		DatabaseName:  dbName,
		Name:          tableName,
		Description:   description,
		Location:      location,
		Columns:       columns,
		PartitionKeys: partitionKeys,
	})
	table.DependsOn = []string{dbName} // table depends on db resource
	resources[tableName] = table

	tableName = "jsonlTable"
	description = "Test table"
	location = cfngen.Sub{Sub: "s3//${Bucket}/" + dbName + "/" + tableName}
	table = NewJSONLTable(&NewTableInput{
		CatalogID:     catalogID,
		DatabaseName:  dbName,
		Name:          tableName,
		Description:   description,
		Location:      location,
		Columns:       columns,
		PartitionKeys: partitionKeys,
	})
	table.DependsOn = []string{dbName} // table depends on db resource
	resources[tableName] = table

	cfTemplate := cfngen.NewTemplate("Test template", parameters, resources, nil)

	cf, err := cfTemplate.CloudFormation()
	require.NoError(t, err)

	// uncomment to write new expected file
	// require.NoError(t, ioutil.WriteFile(expectedFile, cf, 0644))

	expected, err := ioutil.ReadFile(expectedFile)
	require.NoError(t, err)
	assert.JSONEq(t, string(cf), string(expected))
}
