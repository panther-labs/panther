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

// CloudFormation generation for Glue tables from parser event struct

import (
	"bytes"
	"reflect"
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/tools/cfngen"
)

var (
	CatalogIDRef = cfngen.Ref{Ref: "AWS::AccountId"} // macro expand to accountId for CF

	// Glue mappings for timestamps.
	glueMappings = []CustomMapping{
		{
			From: reflect.TypeOf(timestamp.RFC3339{}),
			To:   awsglue.GlueTimestampType,
		},
		{
			From: reflect.TypeOf(timestamp.ANSICwithTZ{}),
			To:   awsglue.GlueTimestampType,
		},
	}
)

// Re-map characters not allow in CF names consistently
func cfResourceClean(name string) string {
	return strings.Replace(name, "_", "", -1) // CF resources must be alphanum
}

// Output CloudFormation for all 'tables'
func GenerateCloudFormation(tables []*awsglue.GlueMetadata) (cf []byte, err error) {
	const bucketParam = "ProcessedDataBucket"
	parameters := make(map[string]interface{})
	parameters[bucketParam] = &cfngen.Parameter{
		Type:        "String",
		Description: "Bucket to hold data for tables",
	}

	// all tables are in one database
	db := NewDatabase(CatalogIDRef, awsglue.InternalDatabaseName, awsglue.InternalDatabaseDescription)
	resources := map[string]interface{}{
		cfResourceClean(awsglue.InternalDatabaseName): db,
	}

	// output database name
	outputs := map[string]interface{}{
		"PantherDatabase": &cfngen.Output{
			Description: "Database over Panther S3 data",
			Value:       cfngen.Ref{Ref: cfResourceClean(awsglue.InternalDatabaseName)},
		},
	}

	// add tables for all parsers
	for _, t := range tables {
		location := cfngen.Sub{Sub: "s3://${" + bucketParam + "}/" + t.S3Prefix()}

		columns := InferJSONColumns(t.EventStruct(), glueMappings...)

		// NOTE: current all sources are JSONL (could add a type to LogParserMetadata struct if we need more types)
		table := NewJSONLTable(&NewTableInput{
			CatalogID:     CatalogIDRef,
			DatabaseName:  cfngen.Ref{Ref: cfResourceClean(awsglue.InternalDatabaseName)},
			Name:          t.TableName(),
			Description:   t.Description(),
			Location:      location,
			Columns:       columns,
			PartitionKeys: getPartitionKeys(t),
		})

		tableResource := cfResourceClean(t.DatabaseName() + t.TableName())
		resources[tableResource] = table
	}

	// generate CF using cfngen
	cfTemplate := cfngen.NewTemplate("Panther Glue Resources", parameters, resources, outputs)
	buffer := bytes.Buffer{}
	err = cfTemplate.WriteCloudFormation(&buffer)
	return buffer.Bytes(), err
}

func getPartitionKeys(t *awsglue.GlueMetadata) (partitions []Column) {
	partitions = []Column{
		{Name: "year", Type: "int", Comment: "year"},
	}
	if t.Timebin() >= awsglue.GlueTableMonthly {
		partitions = append(partitions, Column{Name: "month", Type: "int", Comment: "month"})
	}
	if t.Timebin() >= awsglue.GlueTableDaily {
		partitions = append(partitions, Column{Name: "day", Type: "int", Comment: "day"})
	}
	if t.Timebin() >= awsglue.GlueTableHourly {
		partitions = append(partitions, Column{Name: "hour", Type: "int", Comment: "hour"})
	}
	return
}
