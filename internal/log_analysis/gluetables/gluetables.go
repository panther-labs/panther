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
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/awsutils"
)

// DeployedLogTables returns the glue tables from the registry that have been deployed
func DeployedLogTables(glueClient glueiface.GlueAPI) (deployedLogTables []*awsglue.GlueTableMetadata, err error) {
	for _, gm := range registry.AvailableTables() {
		_, err := awsglue.GetTable(glueClient, gm.DatabaseName(), gm.TableName())
		if err != nil {
			if awsutils.IsAnyError(err, glue.ErrCodeEntityNotFoundException) {
				continue
			} else {
				return nil, errors.Wrapf(err, "failure checking existence of %s.%s",
					gm.DatabaseName(), gm.TableName())
			}
		}
		deployedLogTables = append(deployedLogTables, gm)
	}

	return deployedLogTables, nil
}

// DeployedLogTypes scans glue API to filter log types with deployed tables
func DeployedLogTypes(ctx context.Context, glueClient glueiface.GlueAPI, logTypes []string) ([]string, error) {
	dbName := awsglue.LogProcessingDatabaseName
	index := make(map[string]string, len(logTypes))
	deployed := make([]string, 0, len(logTypes))
	for _, logType := range logTypes {
		tableName := awsglue.GetTableName(logType)
		index[tableName] = logType
	}
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
	input := glue.GetTablesInput{
		DatabaseName: &dbName,
	}
	err := glueClient.GetTablesPagesWithContext(ctx, &input, scan)
	if err != nil {
		return nil, err
	}
	return deployed, nil
}

// DeployedTablesSignature returns a string "signature" for the schema of the deployed tables used to detect change
func DeployedTablesSignature(glueClient glueiface.GlueAPI) (deployedLogTablesSignature string, err error) {
	deployedLogTables, err := DeployedLogTables(glueClient)
	if err != nil {
		return "", err
	}

	allTables := ExpandLogTables(deployedLogTables...)

	return BuildSignature(allTables...)
}

// Expand log tables expands tables from the log processing database to include additional tables (rules, ruleErrors)
func ExpandLogTables(tables ...*awsglue.GlueTableMetadata) (expanded []*awsglue.GlueTableMetadata) {
	expanded = make([]*awsglue.GlueTableMetadata, 0, 3*len(tables))
	for _, table := range tables {
		if table.DatabaseName() != awsglue.LogProcessingDatabaseName {
			continue
		}
		expanded = append(expanded, table, table.RuleTable(), table.RuleErrorTable())
	}
	return
}

func BuildSignature(tables ...*awsglue.GlueTableMetadata) (string, error) {
	tableSignatures := make([]string, 0, len(tables))
	for _, table := range tables {
		sig, err := table.Signature()
		if err != nil {
			return "", err
		}
		tableSignatures = append(tableSignatures, sig)
	}
	sort.Strings(tableSignatures) // need consistent order
	hash := sha256.New()
	for i := range tableSignatures {
		_, _ = hash.Write([]byte(tableSignatures[i]))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
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
