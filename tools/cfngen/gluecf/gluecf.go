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

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/tools/cfngen"
)

var (
	CatalogIDRef = cfngen.Ref{Ref: "AWS::AccountId"} // macro expand to accountId for CF

	// GlueMappings for custom Panther types.
	GlueMappings = []CustomMapping{
		{
			From: reflect.TypeOf(timestamp.RFC3339{}),
			To:   awsglue.GlueTimestampType,
		},
		{
			From: reflect.TypeOf(timestamp.ANSICwithTZ{}),
			To:   awsglue.GlueTimestampType,
		},
		{
			From: reflect.TypeOf(parsers.PantherAnyString{}),
			To:   "array<string>",
		},
		{
			From: reflect.TypeOf(jsoniter.RawMessage{}),
			To:   "string",
		},
	}
)

// Output CloudFormation for all 'tables'
func GenerateTables(tables []*awsglue.GlueMetadata) (cf []byte, err error) {
	const bucketParam = "ProcessedDataBucket"
	parameters := make(map[string]interface{})
	parameters[bucketParam] = &cfngen.Parameter{
		Type:        "String",
		Description: "Bucket to hold data for tables",
	}

	tablesDB := NewDatabase(CatalogIDRef, awsglue.TablesDatabaseName, awsglue.TablesDatabaseDescription)
	viewsDB := NewDatabase(CatalogIDRef, awsglue.ViewsDatabaseName, awsglue.ViewsDatabaseDescription)
	resources := map[string]interface{}{
		cfngen.SanitizeResourceName(awsglue.TablesDatabaseName): tablesDB,
		cfngen.SanitizeResourceName(awsglue.ViewsDatabaseName):  viewsDB,
	}

	// output database name
	outputs := map[string]interface{}{
		"PantherTablesDatabase": &cfngen.Output{
			Description: awsglue.TablesDatabaseDescription,
			Value:       cfngen.Ref{Ref: cfngen.SanitizeResourceName(awsglue.TablesDatabaseName)},
		},
		"PantherViewsDatabase": &cfngen.Output{
			Description: awsglue.ViewsDatabaseDescription,
			Value:       cfngen.Ref{Ref: cfngen.SanitizeResourceName(awsglue.ViewsDatabaseName)},
		},
	}

	// add tables for all parsers
	for _, t := range tables {
		location := cfngen.Sub{Sub: "s3://${" + bucketParam + "}/" + t.S3Prefix()}

		columns := InferJSONColumns(t.EventStruct(), GlueMappings...)

		// NOTE: current all sources are JSONL (could add a type to LogParserMetadata struct if we need more types)
		table := NewJSONLTable(&NewTableInput{
			CatalogID:     CatalogIDRef,
			DatabaseName:  cfngen.Ref{Ref: cfngen.SanitizeResourceName(awsglue.TablesDatabaseName)},
			Name:          t.TableName(),
			Description:   t.Description(),
			Location:      location,
			Columns:       columns,
			PartitionKeys: getPartitionKeys(t),
		})

		tableResource := cfngen.SanitizeResourceName(t.DatabaseName() + t.TableName())
		resources[tableResource] = table
	}

	// generate CF using cfngen
	cfTemplate := cfngen.NewTemplate("Panther Glue Resources", parameters, resources, outputs)
	buffer := bytes.Buffer{}
	err = cfTemplate.WriteCloudFormation(&buffer)
	buffer.WriteString("\n") // add trailing \n that is expected in text files
	return buffer.Bytes(), err
}

func getPartitionKeys(t *awsglue.GlueMetadata) (partitions []Column) {
	for _, partition := range t.PartitionKeys() {
		partitions = append(partitions, Column{
			Name:    partition.Name,
			Type:    partition.Type,
			Comment: partition.Name,
		})
	}
	return partitions
}
