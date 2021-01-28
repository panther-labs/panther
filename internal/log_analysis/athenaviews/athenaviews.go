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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/awsathena"
)

var (
	catalogName = "AwsDataCatalog"
)

type Maker struct {
	athenaClient athenaiface.AthenaAPI
	workgroup    string
}

func NewMaker(athenaClient athenaiface.AthenaAPI, workgroup string) *Maker {
	return &Maker{
		athenaClient: athenaClient,
		workgroup:    workgroup,
	}
}

type athenaColumn struct {
	athena.Column
}

func (col *athenaColumn) Name() string {
	return *col.Column.Name
}

type athenaTable struct {
	databaseName string
	tableData    *athena.TableMetadata
}

func (at *athenaTable) DatabaseName() string {
	return at.databaseName
}

func (at *athenaTable) Name() string {
	return *at.tableData.Name
}

func (at *athenaTable) Columns() (cols []Column) {
	cols = make([]Column, len(at.tableData.Columns))
	for i, col := range at.tableData.Columns {
		cols[i] = &athenaColumn{*col}
	}
	return cols
}

// CreateOrReplaceLogViews will update Athena with all views for the tables provided
func (m *Maker) CreateOrReplaceLogViews() error {
	// loop over available tables, generate view over all Panther tables in glue catalog
	sqlStatements, err := NewViewMaker(m).GenerateLogViews()
	if err != nil {
		return err
	}
	for _, sql := range sqlStatements {
		_, err := awsathena.RunQuery(m.athenaClient, m.workgroup, pantherdb.ViewsDatabase, sql)
		if err != nil {
			return errors.Wrapf(err, "CreateOrReplaceViews() failed for WorkGroup %s for: %s", m.workgroup, sql)
		}
	}
	return err
}

func (m *Maker) ListTables(databaseName string) (tables []Table, err error) {
	input := &athena.ListTableMetadataInput{
		CatalogName:  &catalogName,
		DatabaseName: aws.String(databaseName),
	}
	err = m.athenaClient.ListTableMetadataPages(input, func(page *athena.ListTableMetadataOutput, lastPage bool) bool {
		for _, table := range page.TableMetadataList {
			// skip ddb tables!
			if table.Parameters != nil && table.Parameters["sourceTable"] != nil {
				continue
			}
			tables = append(tables, &athenaTable{
				databaseName: databaseName,
				tableData:    table,
			})
		}
		return false
	})

	return tables, err
}

// Abstract code to create SQL views given a TableLister from a specific database

type Column interface {
	Name() string
}

type Table interface {
	DatabaseName() string
	Name() string
	Columns() []Column
}

type TableLister interface {
	ListTables(databaseName string) (tables []Table, err error)
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
func (vm *ViewMaker) GenerateLogViews() (sqlStatements []string, err error) {
	var allTables []Table // collect so that at the end we can make 1 view over all tables

	createView := func(databaseName, viewName string) error {
		sqlStatement, tables, err := vm.createView(databaseName, viewName)
		if err != nil {
			return err
		}
		if sqlStatement != "" {
			sqlStatements = append(sqlStatements, sqlStatement)
		}
		allTables = append(allTables, tables...)
		return nil
	}

	err = createView(pantherdb.LogProcessingDatabase, "all_logs")
	if err != nil {
		return nil, err
	}

	err = createView(pantherdb.CloudSecurityDatabase, "all_cloudsecurity")
	if err != nil {
		return nil, err
	}

	err = createView(pantherdb.RuleMatchDatabase, "all_rule_matches")
	if err != nil {
		return nil, err
	}

	err = createView(pantherdb.RuleErrorsDatabase, "all_rule_errors")
	if err != nil {
		return nil, err
	}

	// always last, create one view over everything
	sqlStatement, err := generateViewAllDatabases(allTables)
	if err != nil {
		return nil, err
	}
	if sqlStatement != "" {
		sqlStatements = append(sqlStatements, sqlStatement)
	}

	return sqlStatements, nil
}

/*
// generateViewAllLogs creates a view over all log sources in log db using "panther" fields
func (vm *ViewMaker) generateViewAllLogs() (sql string, tables []Table, err error) {
	tables, err = vm.tableLister.ListTables(pantherdb.LogProcessingDatabase)
	if err != nil {
		return "", tables, err
	}
	sql, err = generateView("all_logs", tables)
	return sql, tables, err
}

// generateViewAllCloudSecurity creates a view over all log sources in cloudsecurity db using "panther" fields
func (vm *ViewMaker) generateViewAllCloudSecurity() (sql string, tables []Table, err error) {
	tables, err = vm.tableLister.ListTables(pantherdb.CloudSecurityDatabase)
	if err != nil {
		return "", tables, err
	}
	sql, err = generateView("all_cloudsecurity", tables)
	return sql, tables, err
}

// generateViewAllRuleMatches creates a view over all log sources in rule match db the using "panther" fields
func (vm *ViewMaker) generateViewAllRuleMatches() (sql string, tables []Table, err error) {
	tables, err = vm.tableLister.ListTables(pantherdb.RuleMatchDatabase)
	if err != nil {
		return "", tables, err
	}
	sql, err = generateView("all_rule_matches", tables)
	return sql, tables, err
}

// generateViewAllRuleErrors creates a view over all log sources in rule error db the using "panther" fields
func (vm *ViewMaker) generateViewAllRuleErrors() (sql string, tables []Table, err error) {
	tables, err = vm.tableLister.ListTables(pantherdb.RuleErrorsDatabase)
	if err != nil {
		return "", tables, err
	}
	sql, err = generateView("all_rule_errors", tables)
	return sql, tables, err
}
*/

// createView creates a view over all tables in the db the using "panther" fields
func (vm *ViewMaker) createView(databaseName, viewName string) (sql string, tables []Table, err error) {
	tables, err = vm.tableLister.ListTables(databaseName)
	if err != nil {
		return "", tables, err
	}
	sql, err = generateView(viewName, tables)
	return sql, tables, err
}

// generateViewAllDatabases() creates a view over all data by taking all tables created in previous views
func generateViewAllDatabases(tables []Table) (sql string, err error) {
	return generateView("all_databases", tables)
}

// generateView merges all the tables into a single view
func generateView(viewName string, tables []Table) (sql string, err error) {
	if len(tables) == 0 {
		return "", nil
	}

	// collect the Panther fields, add "NULL" for fields not present in some tables but present in others
	pantherViewColumns, err := newPantherViewColumns(tables)
	if err != nil {
		return "", err
	}

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

	return strings.Join(sqlLines, "\n"), nil
}

// used to collect the UNION of all Panther "p_" fields for the view for each table
type pantherViewColumns struct {
	allColumns     []string                       // union of all columns over all tables as sorted slice
	allColumnsSet  map[string]struct{}            // union of all columns over all tables as map
	columnsByTable map[string]map[string]struct{} // table -> map of column names in that table
}

func newPantherViewColumns(tables []Table) (*pantherViewColumns, error) {
	pvc := &pantherViewColumns{
		allColumnsSet:  make(map[string]struct{}),
		columnsByTable: make(map[string]map[string]struct{}),
	}

	for _, table := range tables {
		if err := pvc.collectViewColumns(table); err != nil {
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
func (pvc *pantherViewColumns) collectViewColumns(table Table) error {
	var selectColumns []string
	for _, col := range table.Columns() {
		if strings.HasPrefix(col.Name(), parsers.PantherFieldPrefix) { // only Panther columns
			selectColumns = append(selectColumns, col.Name())
		}
	}

	tableColumns := make(map[string]struct{})
	pvc.columnsByTable[table.Name()] = tableColumns

	for _, column := range selectColumns {
		tableColumns[column] = struct{}{}
		if _, exists := pvc.allColumnsSet[column]; !exists {
			pvc.allColumnsSet[column] = struct{}{}
		}
	}
	return nil
}

func (pvc *pantherViewColumns) viewColumns(table Table) string {
	tableColumns := pvc.columnsByTable[table.Name()]
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
