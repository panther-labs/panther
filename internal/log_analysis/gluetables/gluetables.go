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
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

// DeployedLogTables returns the glue tables from the registry that have been deployed
func DeployedLogTables(glueClient glueiface.GlueAPI) (deployedLogTables []*awsglue.GlueTableMetadata, err error) {
	for _, gm := range registry.AvailableTables() {
		_, err := awsglue.GetTable(glueClient, gm.DatabaseName(), gm.TableName())
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
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

// DeployedTablesSignature returns a string "signature" for the schema of the deployed tables used to detect change
func DeployedTablesSignature(glueClient glueiface.GlueAPI) (deployedLogTablesSignature string, err error) {
	deployedLogTables, err := DeployedLogTables(glueClient)
	if err != nil {
		return "", err
	}

	tableSignatures := make([]string, 0, 2*len(deployedLogTables))
	for _, logTable := range deployedLogTables {
		sig, err := logTable.Signature()
		if err != nil {
			return "", err
		}
		tableSignatures = append(tableSignatures, sig)

		// the corresponding rule table shares the same structure as the log table + some columns
		ruleTable := logTable.RuleTable()
		sig, err = ruleTable.Signature()
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

// CreateOrUpdateGlueTablesForLogType uses the parser registry to get the table meta data and creates tables in the glue catalog
func CreateOrUpdateGlueTablesForLogType(glueClient glueiface.GlueAPI, logType,
	bucket string) (*awsglue.GlueTableMetadata, *awsglue.GlueTableMetadata, error) {

	logTable := registry.Lookup(logType).GlueTableMetadata() // get the table description
	ruleTable, err := CreateOrUpdateGlueTables(glueClient, bucket, logTable)
	return logTable, ruleTable, err
}

// CreateOrUpdateGlueTables, given a log meta data table, creates a log and rule table in the glue catalog
func CreateOrUpdateGlueTables(glueClient glueiface.GlueAPI, bucket string,
	logTable *awsglue.GlueTableMetadata) (ruleTable *awsglue.GlueTableMetadata, err error) {

	err = logTable.CreateOrUpdateTable(glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			logTable.DatabaseName(), logTable.TableName())
	}

	// the corresponding rule table shares the same structure as the log table + some columns
	ruleTable = logTable.RuleTable()
	err = ruleTable.CreateOrUpdateTable(glueClient, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create glue log table for %s.%s",
			ruleTable.DatabaseName(), ruleTable.TableName())
	}

	return ruleTable, nil
}
