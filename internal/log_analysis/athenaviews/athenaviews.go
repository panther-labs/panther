package athenaviews

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
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/core/pantherdb"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/pkg/awsathena"
)

// CreateOrReplaceViews will update Athena with all views for the tables provided
func CreateOrReplaceViews(athenaClient athenaiface.AthenaAPI, workgroup string, deployedLogTables []*awsglue.GlueTableMetadata) error {
	if len(deployedLogTables) == 0 { // nothing to do
		return nil
	}
	// loop over available tables, generate view over all Panther tables in glue catalog
	sqlStatements, err := GenerateLogViews(deployedLogTables)
	if err != nil {
		return err
	}
	for _, sql := range sqlStatements {
		_, err := awsathena.RunQuery(athenaClient, workgroup, pantherdb.ViewsDatabase, sql)
		if err != nil {
			return errors.Wrap(err, "CreateOrReplaceViews() failed")
		}
	}
	return err
}

// GenerateLogViews creates useful Athena views in the panther views database
func GenerateLogViews(tables []*awsglue.GlueTableMetadata) (sqlStatements []string, err error) {
	if len(tables) == 0 {
		return nil, errors.New("no tables specified for GenerateLogViews()")
	}
	sqlStatement, err := generateViewAllLogs(tables)
	if err != nil {
		return nil, err
	}
	sqlStatements = append(sqlStatements, sqlStatement)
	sqlStatement, err = generateViewAllRuleMatches(tables)
	if err != nil {
		return nil, err
	}
	sqlStatements = append(sqlStatements, sqlStatement)
	sqlStatement, err = generateViewAllRuleErrors(tables)
	if err != nil {
		return nil, err
	}
	sqlStatements = append(sqlStatements, sqlStatement)
	// add future views here
	return sqlStatements, nil
}

// generateViewAllLogs creates a view over all log sources in log db using "panther" fields
func generateViewAllLogs(tables []*awsglue.GlueTableMetadata) (sql string, err error) {
	return generateViewAllHelper("all_logs", tables, []awsglue.Column{})
}

// generateViewAllRuleMatches creates a view over all log sources in rule match db the using "panther" fields
func generateViewAllRuleMatches(tables []*awsglue.GlueTableMetadata) (sql string, err error) {
	// the rule match tables share the same structure as the logs with some extra columns
	var ruleTables []*awsglue.GlueTableMetadata
	for _, table := range tables {
		ruleTable := awsglue.NewGlueTableMetadata(
			pantherdb.RuleData.Database(), table.LogType(), table.Description(), awsglue.GlueTableHourly, table.EventStruct())
		ruleTables = append(ruleTables, ruleTable)
	}
	return generateViewAllHelper("all_rule_matches", ruleTables, awsglue.RuleMatchColumns)
}

// generateViewAllRuleErrors creates a view over all log sources in rule error db the using "panther" fields
func generateViewAllRuleErrors(tables []*awsglue.GlueTableMetadata) (sql string, err error) {
	// the rule match tables share the same structure as the logs with some extra columns
	var ruleErrorTables []*awsglue.GlueTableMetadata
	for _, table := range tables {
		ruleTable := awsglue.NewGlueTableMetadata(
			pantherdb.RuleErrors.Database(), table.LogType(), table.Description(), awsglue.GlueTableHourly, table.EventStruct())
		ruleErrorTables = append(ruleErrorTables, ruleTable)
	}
	return generateViewAllHelper("all_rule_errors", ruleErrorTables, awsglue.RuleErrorColumns)
}

func generateViewAllHelper(viewName string, tables []*awsglue.GlueTableMetadata, extraColumns []awsglue.Column) (sql string, err error) {
	// validate they all have the same partition keys
	if len(tables) > 1 {
		// create string of partition for comparison
		genKey := func(partitions []awsglue.PartitionKey) (key string) {
			for _, p := range partitions {
				key += p.Name + p.Type
			}
			return key
		}
		referenceKey := genKey(tables[0].PartitionKeys())
		for _, table := range tables[1:] {
			if referenceKey != genKey(table.PartitionKeys()) {
				return "", errors.New("all tables do not share same partition keys for generateViewAllHelper()")
			}
		}
	}

	// collect the Panther fields, add "NULL" for fields not present in some tables but present in others
	pantherViewColumns, err := newPantherViewColumns(tables, extraColumns)
	if err != nil {
		return "", err
	}

	var sqlLines []string
	sqlLines = append(sqlLines, fmt.Sprintf("create or replace view %s.%s as", pantherdb.ViewsDatabase, viewName))

	for i, table := range tables {
		sqlLines = append(sqlLines, fmt.Sprintf("select %s from %s.%s",
			pantherViewColumns.viewColumns(table), table.DatabaseName(), table.TableName()))
		if i < len(tables)-1 {
			sqlLines = append(sqlLines, "\tunion all")
		}
	}

	sqlLines = append(sqlLines, ";\n")

	return strings.Join(sqlLines, "\n"), nil
}

// used to collect the UNION of all Panther "p_" fields for the view for each table
type pantherViewColumns struct {
	allColumns     []string                       // union of all columns over all tables as sorted slice
	allColumnsSet  map[string]struct{}            // union of all columns over all tables as map
	columnsByTable map[string]map[string]struct{} // table -> map of column names in that table
}

func newPantherViewColumns(tables []*awsglue.GlueTableMetadata, extraColumns []awsglue.Column) (*pantherViewColumns, error) {
	pvc := &pantherViewColumns{
		allColumnsSet:  make(map[string]struct{}),
		columnsByTable: make(map[string]map[string]struct{}),
	}

	for _, table := range tables {
		if err := pvc.inferViewColumns(table, extraColumns); err != nil {
			return nil, err
		}
	}

	// convert set to sorted slice
	pvc.allColumns = make([]string, 0, len(pvc.allColumnsSet))
	for column := range pvc.allColumnsSet {
		pvc.allColumns = append(pvc.allColumns, column)
	}
	sort.Strings(pvc.allColumns) // order needs to be preserved

	return pvc, nil
}
func (pvc *pantherViewColumns) inferViewColumns(table *awsglue.GlueTableMetadata, extraColumns []awsglue.Column) error {
	// NOTE: in the future when we tag columns for views, the mapping  would be resolved here
	columns, err := glueschema.InferColumns(table.EventStruct())
	if err != nil {
		return err
	}
	columns = append(columns, extraColumns...)
	var selectColumns []string
	for _, col := range columns {
		if strings.HasPrefix(col.Name, parsers.PantherFieldPrefix) { // only Panther columns
			selectColumns = append(selectColumns, col.Name)
		}
	}

	for _, partitionKey := range table.PartitionKeys() { // they all have same keys, pick first table
		selectColumns = append(selectColumns, partitionKey.Name)
	}

	tableColumns := make(map[string]struct{})
	pvc.columnsByTable[table.TableName()] = tableColumns

	for _, column := range selectColumns {
		tableColumns[column] = struct{}{}
		if _, exists := pvc.allColumnsSet[column]; !exists {
			pvc.allColumnsSet[column] = struct{}{}
		}
	}
	return nil
}

func (pvc *pantherViewColumns) viewColumns(table *awsglue.GlueTableMetadata) string {
	tableColumns := pvc.columnsByTable[table.TableName()]
	selectColumns := make([]string, 0, len(pvc.allColumns))
	for _, column := range pvc.allColumns {
		selectColumn := column
		if _, exists := tableColumns[column]; !exists { // fill in missing columns with NULL
			selectColumn = "NULL AS " + selectColumn
		}
		selectColumns = append(selectColumns, selectColumn)
	}

	return strings.Join(selectColumns, ",")
}
