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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

type table1Event struct {
	parsers.PantherLog
	FavoriteFruit string `description:"test field"`
}

type table2Event struct {
	awslogs.AWSPantherLog
	FavoriteColor string `description:"test field"`
}

type testColumn struct {
	glueschema.Column
}

func (tc *testColumn) Name() string {
	return tc.Column.Name
}

func (tc *testColumn) IsPartition() bool {
	return false
}

type testTable struct {
	awsglue.GlueTableMetadata
}

func (at *testTable) Name() string {
	return at.GlueTableMetadata.TableName()
}

func (at *testTable) Columns() (cols []Column) {
	columns, _ := glueschema.InferColumns(at.EventStruct())
	cols = make([]Column, len(columns))
	for i, col := range columns {
		cols[i] = &testColumn{Column: col}
	}
	return cols
}

type testTableLister struct {
	tables []Table
}

func (l *testTableLister) ListTables(_ context.Context, databaseName string) (tables []Table, err error) {
	if databaseName == pantherdb.LogProcessingDatabase {
		return l.tables, nil
	}
	return []Table{}, nil
}

func TestGenerateViewAllLogs(t *testing.T) {
	var table1 = &testTable{GlueTableMetadata: *awsglue.NewGlueTableMetadata(pantherdb.LogProcessingDatabase,
		"table1", "test table1", awsglue.GlueTableHourly, &table1Event{})}
	var table2 = &testTable{GlueTableMetadata: *awsglue.NewGlueTableMetadata(pantherdb.LogProcessingDatabase,
		"table2", "test table2", awsglue.GlueTableHourly, &table2Event{})}

	var lister testTableLister
	lister.tables = []Table{table1, table2}

	// nolint (lll)
	expectedAllLogsSQL := `create or replace view panther_views.all_logs as
select 'panther_logs' AS p_db_name,NULL AS p_any_aws_account_ids,NULL AS p_any_aws_arns,NULL AS p_any_aws_instance_ids,NULL AS p_any_aws_tags,p_any_domain_names,p_any_ip_addresses,p_any_md5_hashes,p_any_sha1_hashes,p_any_sha256_hashes,p_event_time,p_log_type,p_parse_time,p_row_id,p_source_id,p_source_label from panther_logs.table1
	union all
select 'panther_logs' AS p_db_name,p_any_aws_account_ids,p_any_aws_arns,p_any_aws_instance_ids,p_any_aws_tags,p_any_domain_names,p_any_ip_addresses,p_any_md5_hashes,p_any_sha1_hashes,p_any_sha256_hashes,p_event_time,p_log_type,p_parse_time,p_row_id,p_source_id,p_source_label from panther_logs.table2
;
`
	// nolint (lll)
	expectedAllDatabasesSQL := `create or replace view panther_views.all_databases as
select 'panther_logs' AS p_db_name,NULL AS p_any_aws_account_ids,NULL AS p_any_aws_arns,NULL AS p_any_aws_instance_ids,NULL AS p_any_aws_tags,p_any_domain_names,p_any_ip_addresses,p_any_md5_hashes,p_any_sha1_hashes,p_any_sha256_hashes,p_event_time,p_log_type,p_parse_time,p_row_id,p_source_id,p_source_label from panther_logs.table1
	union all
select 'panther_logs' AS p_db_name,p_any_aws_account_ids,p_any_aws_arns,p_any_aws_instance_ids,p_any_aws_tags,p_any_domain_names,p_any_ip_addresses,p_any_md5_hashes,p_any_sha1_hashes,p_any_sha256_hashes,p_event_time,p_log_type,p_parse_time,p_row_id,p_source_id,p_source_label from panther_logs.table2
;
`
	sqlStatements, err := NewViewMaker(&lister).GenerateLogViews(context.Background())
	require.NoError(t, err)
	require.Len(t, sqlStatements, 2)
	require.Equal(t, expectedAllLogsSQL, sqlStatements[0])
	require.Equal(t, expectedAllDatabasesSQL, sqlStatements[1])
}
