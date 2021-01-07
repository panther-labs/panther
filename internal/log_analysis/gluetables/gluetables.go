package gluetables

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
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

// DeployedLogTypes scans glue API to filter log types with deployed tables
func DeployedLogTypes(ctx context.Context, glueClient glueiface.GlueAPI, logTypes []string) ([]string, error) {
	dbNames := []string{pantherdb.LogProcessingDatabase, pantherdb.CloudSecurityDatabase}
	index := make(map[string]string, len(logTypes))
	deployed := make([]string, 0, len(logTypes))

	// set up filter via map
	for _, logType := range logTypes {
		tableName := pantherdb.TableName(logType)
		index[tableName] = logType
	}

	// collects logTypes
	scan := func(page *glue.GetTablesOutput, _ bool) bool {
		for _, table := range page.TableList {
			tableName := aws.StringValue(table.Name)
			logType, ok := index[tableName]
			if ok {
				deployed = append(deployed, logType)
			}
		}
		return true
	}

	// loop over each database, collecting the logTypes
	for i := range dbNames {
		input := glue.GetTablesInput{
			DatabaseName: &dbNames[i],
		}
		err := glueClient.GetTablesPagesWithContext(ctx, &input, scan)
		if err != nil {
			return nil, err
		}
	}

	return deployed, nil
}

type TablesForLogType struct {
	LogTable       *awsglue.GlueTableMetadata
	RuleTable      *awsglue.GlueTableMetadata
	RuleErrorTable *awsglue.GlueTableMetadata
}

// CreateOrUpdateGlueTables, given a log meta data table, creates all tables related to this log table in the glue catalog.
func CreateOrUpdateGlueTables(glueClient glueiface.GlueAPI, bucket string,
	logTable *awsglue.GlueTableMetadata) (*TablesForLogType, error) {

	// Create the log table
	err := logTable.CreateOrUpdateTable(glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			logTable.DatabaseName(), logTable.TableName())
	}

	// the corresponding rule table shares the same structure as the log table + some columns
	ruleTable := logTable.RuleTable()
	err = ruleTable.CreateOrUpdateTable(glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			ruleTable.DatabaseName(), ruleTable.TableName())
	}

	// the corresponding rule errors table shares the same structure as the log table + some columns
	ruleErrorTable := logTable.RuleErrorTable()
	err = ruleErrorTable.CreateOrUpdateTable(glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			ruleErrorTable.DatabaseName(), ruleErrorTable.TableName())
	}

	return &TablesForLogType{
		LogTable:       logTable,
		RuleTable:      ruleTable,
		RuleErrorTable: ruleErrorTable,
	}, nil
}

// CreateTablesIfNotExist creates all tables related to a log table in the glue catalog if they don't already exist.
func CreateTablesIfNotExist(ctx context.Context, glueClient glueiface.GlueAPI, bucket string,
	logTable *awsglue.GlueTableMetadata) (*TablesForLogType, error) {

	// Create the log table
	_, err := logTable.CreateTableIfNotExists(ctx, glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			logTable.DatabaseName(), logTable.TableName())
	}

	// the corresponding rule table shares the same structure as the log table + some columns
	ruleTable := logTable.RuleTable()
	_, err = ruleTable.CreateTableIfNotExists(ctx, glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			ruleTable.DatabaseName(), ruleTable.TableName())
	}

	// the corresponding rule errors table shares the same structure as the log table + some columns
	ruleErrorTable := logTable.RuleErrorTable()
	_, err = ruleErrorTable.CreateTableIfNotExists(ctx, glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			ruleErrorTable.DatabaseName(), ruleErrorTable.TableName())
	}

	return &TablesForLogType{
		LogTable:       logTable,
		RuleTable:      ruleTable,
		RuleErrorTable: ruleErrorTable,
	}, nil
}

// UpdateTablesIfExist updates all tables related to this log table in the glue catalog if they already exist.
func UpdateTablesIfExist(ctx context.Context, glueAPI glueiface.GlueAPI, bucket string,
	logTable *awsglue.GlueTableMetadata) (*TablesForLogType, error) {

	// Create the log table
	_, err := logTable.UpdateTableIfExists(ctx, glueAPI, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not update Glue log table for %s.%s",
			logTable.DatabaseName(), logTable.TableName())
	}

	// the corresponding rule table shares the same structure as the log table + some columns
	ruleTable := logTable.RuleTable()
	_, err = ruleTable.UpdateTableIfExists(ctx, glueAPI, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not update glue log table for %s.%s",
			ruleTable.DatabaseName(), ruleTable.TableName())
	}

	// the corresponding rule errors table shares the same structure as the log table + some columns
	ruleErrorTable := logTable.RuleErrorTable()
	_, err = ruleErrorTable.UpdateTableIfExists(ctx, glueAPI, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not update glue log table for %s.%s",
			ruleErrorTable.DatabaseName(), ruleErrorTable.TableName())
	}

	return &TablesForLogType{
		LogTable:       logTable,
		RuleTable:      ruleTable,
		RuleErrorTable: ruleErrorTable,
	}, nil
}

// ResolveTables is a helper to resolve all glue table metadata for all log types
func ResolveTables(ctx context.Context, resolver logtypes.Resolver, logTypes ...string) ([]*awsglue.GlueTableMetadata, error) {
	tables := make([]*awsglue.GlueTableMetadata, len(logTypes))
	for i, logType := range logTypes {
		entry, err := resolver.Resolve(ctx, logType)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, errors.Errorf("unresolved log type %q", logType)
		}
		tables[i] = LogTypeTableMeta(entry)
	}
	return tables, nil
}

func LogTypeTableMeta(entry logtypes.Entry) *awsglue.GlueTableMetadata {
	desc := entry.Describe()
	schema := entry.Schema()
	databaseName := pantherdb.DatabaseName(pantherdb.GetDataType(desc.Name))
	tableName := pantherdb.TableName(desc.Name)
	return awsglue.NewGlueTableMetadata(databaseName, tableName, desc.Description, awsglue.GlueTableHourly, schema)
}
