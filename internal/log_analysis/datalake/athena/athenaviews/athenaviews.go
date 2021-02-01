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
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/datalake/views"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/awsathena"
)

var (
	catalogName = "AwsDataCatalog"
)

type ViewMaker struct {
	athenaClient athenaiface.AthenaAPI
	workgroup    string
}

func NewViewMaker(athenaClient athenaiface.AthenaAPI, workgroup string) *ViewMaker {
	return &ViewMaker{
		athenaClient: athenaClient,
		workgroup:    workgroup,
	}
}

type athenaColumn struct {
	athena.Column
	isPartition bool
}

func (col *athenaColumn) Name() string {
	return *col.Column.Name
}

func (col *athenaColumn) IsPartition() bool {
	return col.isPartition
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

func (at *athenaTable) Columns() (cols []views.Column) {
	cols = make([]views.Column, len(at.tableData.Columns)+len(at.tableData.PartitionKeys))
	for i, col := range at.tableData.Columns {
		cols[i] = &athenaColumn{Column: *col, isPartition: false}
	}
	for i, col := range at.tableData.PartitionKeys {
		cols[i+len(at.tableData.Columns)] = &athenaColumn{Column: *col, isPartition: true}
	}
	return cols
}

// CreateOrReplaceLogViews will update Athena with all views for the tables provided
func (m *ViewMaker) CreateOrReplaceLogViews(ctx context.Context) error {
	// loop over available tables, generate view over all Panther tables in glue catalog
	sqlStatements, err := views.NewViewMaker(m).GenerateLogViews(ctx)
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

func (m *ViewMaker) ListTables(ctx context.Context, databaseName string) (tables []views.Table, err error) {
	input := &athena.ListTableMetadataInput{
		CatalogName:  &catalogName,
		DatabaseName: aws.String(databaseName),
	}
	err = m.athenaClient.ListTableMetadataPagesWithContext(ctx, input,
		func(page *athena.ListTableMetadataOutput, lastPage bool) bool {
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
