package views

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
	"fmt"
	"sort"
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

// Abstract code to create SQL views over the `p_` fields given a TableLister from a specific database

type Column interface {
	Name() string
	IsPartition() bool
}

type Table interface {
	DatabaseName() string
	Name() string
	Columns() []Column
}

type TableLister interface {
	ListTables(ctx context.Context, databaseName string) (tables []Table, err error)
}

type ViewMaker struct {
	tableLister TableLister
}

func NewViewMaker(tableLister TableLister) *ViewMaker {
	return &ViewMaker{
		tableLister: tableLister,
	}
}

// GenerateLogViews creates useful Athena views in the panther views database
func (vm *ViewMaker) GenerateLogViews(ctx context.Context) (sqlStatements []string, err error) {
	var allTables []Table // collect so that at the end we can make 1 view over all tables

	var views = []struct {
		databaseName string
		viewName     string
	}{
		{pantherdb.LogProcessingDatabase, "all_logs"},
		{pantherdb.CloudSecurityDatabase, "all_cloudsecurity"},
		{pantherdb.RuleMatchDatabase, "all_rule_matches"},
		{pantherdb.RuleErrorsDatabase, "all_rule_errors"},
	}
	for _, view := range views {
		sqlStatement, tables, err := vm.createView(ctx, view.databaseName, view.viewName)
		if err != nil {
			return nil, err
		}
		if sqlStatement != "" {
			sqlStatements = append(sqlStatements, sqlStatement)
		}
		allTables = append(allTables, tables...)
	}

	// always last, create one view over everything
	if sqlStatement := generateView("all_databases", allTables); sqlStatement != "" {
		sqlStatements = append(sqlStatements, sqlStatement)
	}

	return sqlStatements, nil
}

// createView creates a view over all tables in the db the using "panther" fields
func (vm *ViewMaker) createView(ctx context.Context, databaseName, viewName string) (sql string, tables []Table, err error) {
	tables, err = vm.tableLister.ListTables(ctx, databaseName)
	if err != nil {
		return "", tables, err
	}
	return generateView(viewName, tables), tables, err
}

// generateView merges all the tables into a single view
func generateView(viewName string, tables []Table) (sql string) {
	if len(tables) == 0 {
		return ""
	}

	// collect the Panther fields, add "NULL" for fields not present in some tables but present in others
	pantherViewColumns := newPantherViewColumns(tables)

	var sqlLines []string
	sqlLines = append(sqlLines, fmt.Sprintf("create or replace view %s.%s as", pantherdb.ViewsDatabase, viewName))

	for i, table := range tables {
		sqlLines = append(sqlLines, fmt.Sprintf("select %s from %s.%s",
			pantherViewColumns.viewColumns(table), table.DatabaseName(), table.Name()))
		if i < len(tables)-1 {
			sqlLines = append(sqlLines, "\tunion all")
		}
	}

	sqlLines = append(sqlLines, ";\n")

	return strings.Join(sqlLines, "\n")
}

// used to collect the UNION of all Panther "p_" fields for the view for each table
type pantherViewColumns struct {
	allColumns     []string                       // union of all columns over all tables as sorted slice
	allColumnsSet  map[string]struct{}            // union of all columns over all tables as map
	columnsByTable map[string]map[string]struct{} // table -> map of column names in that table
}

func newPantherViewColumns(tables []Table) *pantherViewColumns {
	pvc := &pantherViewColumns{
		allColumnsSet:  make(map[string]struct{}),
		columnsByTable: make(map[string]map[string]struct{}),
	}

	for _, table := range tables {
		pvc.collectViewColumns(table)
	}

	// convert set to sorted slice
	pvc.allColumns = make([]string, 0, len(pvc.allColumnsSet))
	for column := range pvc.allColumnsSet {
		pvc.allColumns = append(pvc.allColumns, column)
	}
	sort.Strings(pvc.allColumns) // order needs to be preserved

	return pvc
}

func (pvc *pantherViewColumns) collectViewColumns(table Table) {
	var selectColumns []string
	for _, col := range table.Columns() {
		if strings.HasPrefix(col.Name(), parsers.PantherFieldPrefix) || col.IsPartition() { // only Panther columns or partitions
			selectColumns = append(selectColumns, col.Name())
		}
	}

	tableColumns := make(map[string]struct{})
	pvc.columnsByTable[table.DatabaseName()+table.Name()] = tableColumns

	for _, column := range selectColumns {
		tableColumns[column] = struct{}{}
		if _, exists := pvc.allColumnsSet[column]; !exists {
			pvc.allColumnsSet[column] = struct{}{}
		}
	}
}

func (pvc *pantherViewColumns) viewColumns(table Table) string {
	tableColumns := pvc.columnsByTable[table.DatabaseName()+table.Name()]
	selectColumns := make([]string, 0, len(pvc.allColumns)+1)
	// tag each with database name
	selectColumns = append(selectColumns, fmt.Sprintf("'%s' AS p_db_name", table.DatabaseName()))
	for _, column := range pvc.allColumns {
		selectColumn := column
		if _, exists := tableColumns[column]; !exists { // fill in missing columns with NULL
			selectColumn = "NULL AS " + selectColumn
		}
		selectColumns = append(selectColumns, selectColumn)
	}
	return strings.Join(selectColumns, ",")
}
