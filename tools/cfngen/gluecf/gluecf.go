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
			From: reflect.TypeOf(timestamp.UnixMillisecond{}),
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

	// RuleMatchColumns are columns added by the rules engine
	RuleMatchColumns = []Column{
		{
			Name:    "p_rule_id",
			Type:    "string",
			Comment: "Rule id",
		},
		{
			Name:    "p_alert_id",
			Type:    "string",
			Comment: "Alert id",
		},
		{
			Name:    "p_alert_creation_time",
			Type:    "timestamp",
			Comment: "The time the alert was initially created (first match)",
		},
		{
			Name:    "p_alert_update_time",
			Type:    "timestamp",
			Comment: "The time the alert last updated (last match)",
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

	logsDB := NewDatabase(CatalogIDRef, awsglue.LogProcessingDatabaseName, awsglue.LogProcessingDatabaseDescription)
	ruleMatchDB := NewDatabase(CatalogIDRef, awsglue.RuleMatchDatabaseName, awsglue.RuleMatchDatabaseDescription)
	viewsDB := NewDatabase(CatalogIDRef, awsglue.ViewsDatabaseName, awsglue.ViewsDatabaseDescription)
	resources := map[string]interface{}{
		cfngen.SanitizeResourceName(awsglue.LogProcessingDatabaseName): logsDB,
		cfngen.SanitizeResourceName(awsglue.RuleMatchDatabaseName):     ruleMatchDB,
		cfngen.SanitizeResourceName(awsglue.ViewsDatabaseName):         viewsDB,
	}

	// output databases
	outputs := map[string]interface{}{
		"PantherLogsDatabase": &cfngen.Output{
			Description: awsglue.LogProcessingDatabaseDescription,
			Value:       cfngen.Ref{Ref: cfngen.SanitizeResourceName(awsglue.LogProcessingDatabaseName)},
		},
		"PantherRuleMatchDatabase": &cfngen.Output{
			Description: awsglue.RuleMatchDatabaseDescription,
			Value:       cfngen.Ref{Ref: cfngen.SanitizeResourceName(awsglue.RuleMatchDatabaseName)},
		},
		"PantherViewsDatabase": &cfngen.Output{
			Description: awsglue.ViewsDatabaseDescription,
			Value:       cfngen.Ref{Ref: cfngen.SanitizeResourceName(awsglue.ViewsDatabaseName)},
		},
	}

	addTable := func(t *awsglue.GlueMetadata, extraColumns ...Column) {
		location := cfngen.Sub{Sub: "s3://${" + bucketParam + "}/" + t.S3Prefix()}

		columns := InferJSONColumns(t.EventStruct(), GlueMappings...)
		columns = append(columns, extraColumns...)

		// NOTE: currently all sources are JSONL (could add a type to LogParserMetadata struct if we need more types)
		resources[cfngen.SanitizeResourceName(t.DatabaseName()+t.TableName())] = NewJSONLTable(&NewTableInput{
			CatalogID:     CatalogIDRef,
			DatabaseName:  cfngen.Ref{Ref: cfngen.SanitizeResourceName(t.DatabaseName())},
			Name:          t.TableName(),
			Description:   t.Description(),
			Location:      location,
			Columns:       columns,
			PartitionKeys: getPartitionKeys(t),
		})
	}

	// add tables for all parsers, and matching tables for rule matches
	for _, t := range tables {
		addTable(t)
		// add a matching table for rule matches, add the columns that the rules engine appends
		addTable(t.Clone(awsglue.RuleMatchS3Prefix, awsglue.RuleMatchDatabaseName), RuleMatchColumns...)
	}

	// generate CF using cfngen
	return cfngen.NewTemplate("Panther Glue Resources", parameters, resources, outputs).CloudFormation()
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
