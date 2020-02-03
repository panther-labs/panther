package athenaviews

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
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/tools/cfngen/gluecf"
)

// CreateOrReplaceViews will update Athena with all views in the Panther view database
func CreateOrReplaceViews(athenaResultsBucket string) (err error) {
	sess, err := session.NewSession()
	if err != nil {
		return errors.Wrap(err, "CreateOrReplaceViews() failed")
	}
	s3Path := "s3://" + athenaResultsBucket + "/athena/"
	sqlStatements, err := generateSQLViews(registry.AvailableTables())
	if err != nil {
		return err
	}
	for _, sql := range sqlStatements {
		q := awsathena.NewAthenaQuery(sess, awsglue.ViewsDatabaseName, sql, &s3Path) // use default bucket
		err = q.Run()
		if err != nil {
			return errors.Wrap(err, "CreateOrReplaceViews() failed")
		}
		err = q.Wait()
		if err != nil {
			return errors.Wrap(err, "CreateOrReplaceViews() failed")
		}
	}
	return err
}

// generateSQLViews creates useful Athena views in the panther views database
func generateSQLViews(tables []*awsglue.GlueMetadata) (sqlStatements []string, err error) {
	sqlStatement, err := generateViewAllLogs(tables)
	if err != nil {
		return sqlStatements, err
	}
	sqlStatements = append(sqlStatements, sqlStatement)
	// add future views here
	return sqlStatements, nil
}

// generateViewAllLogs creates a view over all log sources using "panther" fields
func generateViewAllLogs(tables []*awsglue.GlueMetadata) (sql string, err error) {
	if len(tables) == 0 {
		return "", errors.New("no tables specified for generateViewAllLogs()")
	}
	// validate they all have the same partition keys
	if len(tables) > 1 {
		// create string of partition for comparison
		genKey := func(partitions []awsglue.Partition) (key string) {
			for _, p := range partitions {
				key += p.Name + p.Type
			}
			return key
		}
		referenceKey := genKey(tables[0].PartitionKeys())
		for _, table := range tables[1:] {
			if referenceKey != genKey(table.PartitionKeys()) {
				return "", errors.New("all tables do not share same partition keys for generateViewAllLogs()")
			}
		}
	}

	// collect the Panther fields, add "NULL" for fields not present in some tables but present in others
	pantherViewColumns := newPantherViewColumns()
	for _, table := range tables {
		pantherViewColumns.inferViewColumns(table)
	}

	var sqlLines []string
	sqlLines = append(sqlLines, fmt.Sprintf("create or replace view %s.all_logs as", awsglue.ViewsDatabaseName))

	for i, table := range tables {
		sqlLines = append(sqlLines, fmt.Sprintf("select %s from %s.%s",
			pantherViewColumns.viewColumns(table), table.DatabaseName(), table.TableName()))
		if i < len(tables)-1 {
			sqlLines = append(sqlLines, fmt.Sprintf("\tunion all"))
		}
	}

	sqlLines = append(sqlLines, fmt.Sprintf(";\n"))

	return strings.Join(sqlLines, "\n"), nil
}

// used to collect the UNION of all Panther "p_" fields for the view for each table
type pantherViewColumns struct {
	allColumns     map[string]struct{}            // union of all columns over all tables
	columnsByTable map[string]map[string]struct{} // table -> map of column names in that table
}

func newPantherViewColumns() *pantherViewColumns {
	return &pantherViewColumns{
		allColumns:     make(map[string]struct{}),
		columnsByTable: make(map[string]map[string]struct{}),
	}
}
func (pvc *pantherViewColumns) inferViewColumns(table *awsglue.GlueMetadata) {
	// NOTE: in the future when we tag columns for views, the mapping  would be resolved here
	columns := gluecf.InferJSONColumns(table.EventStruct(), gluecf.GlueMappings...)
	var selectColumns []string
	for _, col := range columns {
		if strings.HasPrefix(col.Name, "p_") { // only Panther columns
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
		if _, exists := pvc.allColumns[column]; !exists {
			pvc.allColumns[column] = struct{}{}
		}
	}
}

func (pvc *pantherViewColumns) viewColumns(table *awsglue.GlueMetadata) string {
	allColumns := pvc.columns()
	tableColumns := pvc.columnsByTable[table.TableName()]

	selectColumns := make([]string, 0, len(allColumns))
	for _, column := range allColumns {
		selectColumn := column
		if _, exists := tableColumns[column]; !exists { // fill in missing columns with NULL
			selectColumn = "NULL AS " + selectColumn
		}
		selectColumns = append(selectColumns, selectColumn)
	}

	return strings.Join(selectColumns, ",")
}

// return sorted slice of union of all columns over all tables
func (pvc *pantherViewColumns) columns() []string {
	// NOTE: we could cache result but this is not performance intensive code and I do not think the complexity is worth it.
	allColumns := make([]string, 0, len(pvc.allColumns))
	for column := range pvc.allColumns {
		allColumns = append(allColumns, column)
	}
	sort.Strings(allColumns) // order needs to be preserved
	return allColumns
}
