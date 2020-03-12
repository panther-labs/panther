package gluecf

import (
	"fmt"
	"strings"
)

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

// Generate CF for a gluecf table: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html

// Below structs match CF structure

// NOTE: the use of type interface{} allows strings and structs (e.g., cfngen.Ref{} and cfngen.Sub{} )

type Column struct {
	Name    string
	Type    string
	Comment string `json:",omitempty"`
}

type SerdeInfo struct {
	SerializationLibrary string                 `json:",omitempty"`
	Parameters           map[string]interface{} `json:",omitempty"`
}

type StorageDescriptor struct { // nolint
	InputFormat            string
	OutputFormat           string
	Compressed             bool        `json:",omitempty"`
	Location               interface{} // required
	BucketColumns          []Column    `json:",omitempty"`
	SortColumns            []Column    `json:",omitempty"`
	StoredAsSubDirectories bool        `json:",omitempty"`
	SerdeInfo              SerdeInfo
	Columns                []Column
}

type TableInput struct {
	TableType         string
	Name              interface{}
	Description       interface{} `json:",omitempty"`
	StorageDescriptor StorageDescriptor
	PartitionKeys     []Column `json:",omitempty"`
}

type TableProperties struct {
	CatalogID    interface{} `json:"CatalogId"` // required,  string or Ref{}, need json tag to keep linter happy
	DatabaseName interface{}
	TableInput   TableInput
}

type Table struct {
	Type       string
	DependsOn  []string `json:",omitempty"`
	Properties TableProperties
}

// Core function to create a table
func newExternalTable(catalogID, databaseName, name, description interface{}, sd *StorageDescriptor, pks []Column) (db *Table) {
	db = &Table{
		Type: "AWS::Glue::Table",
		Properties: TableProperties{
			CatalogID:    catalogID,
			DatabaseName: databaseName,
			TableInput: TableInput{
				TableType:         "EXTERNAL_TABLE",
				Name:              name,
				Description:       description,
				StorageDescriptor: *sd,
				PartitionKeys:     pks,
			},
		},
	}

	return
}

// inputs to table generation functions
type NewTableInput struct {
	CatalogID     interface{}
	DatabaseName  interface{}
	Name          interface{}
	Description   interface{}
	Location      interface{}
	Columns       []Column
	PartitionKeys []Column
}

func NewParquetTable(input *NewTableInput) (db *Table) {
	sd := &StorageDescriptor{
		InputFormat:  "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
		OutputFormat: "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
		SerdeInfo: SerdeInfo{
			SerializationLibrary: "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe",
			Parameters: map[string]interface{}{
				"serialization.format": "1",
			},
		},
		Location: input.Location,
		Columns:  input.Columns,
	}

	return newExternalTable(input.CatalogID, input.DatabaseName, input.Name, input.Description, sd, input.PartitionKeys)
}

func NewJSONLTable(input *NewTableInput) (db *Table) {
	descriptorParameters := map[string]interface{}{
		"serialization.format": "1",
		"case.insensitive":     "false", // Need to be case sensitive to deal with columns that have same name but different casing
	}

	// Adding mapping for column names. This is required when columns are case sensitive
	for _, column := range input.Columns {
		descriptorParameters[fmt.Sprintf("mapping.%s", strings.ToLower(column.Name))] = column.Name
	}

	sd := &StorageDescriptor{
		InputFormat:  "org.apache.hadoop.mapred.TextInputFormat",
		OutputFormat: "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
		SerdeInfo: SerdeInfo{
			SerializationLibrary: "org.openx.data.jsonserde.JsonSerDe",
			Parameters:           descriptorParameters,
		},
		Location: input.Location,
		Columns:  input.Columns,
	}

	return newExternalTable(input.CatalogID, input.DatabaseName, input.Name, input.Description, sd, input.PartitionKeys)
}
