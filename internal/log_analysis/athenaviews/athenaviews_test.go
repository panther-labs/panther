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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/core/pantherdb"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
)

type table1Event struct {
	parsers.PantherLog
	FavoriteFruit string `description:"test field"`
}

type table2Event struct {
	awslogs.AWSPantherLog
	FavoriteColor string `description:"test field"`
}

func TestGenerateViewAllLogs(t *testing.T) {
	table1 := awsglue.NewGlueTableMetadata(pantherdb.LogData, "table1", "test table1", awsglue.GlueTableHourly, &table1Event{})
	table2 := awsglue.NewGlueTableMetadata(pantherdb.LogData, "table2", "test table2", awsglue.GlueTableHourly, &table2Event{})
	// nolint (lll)
	expectedSQL := `create or replace view panther_views.all_logs as
select day,hour,month,NULL AS p_any_aws_account_ids,NULL AS p_any_aws_arns,NULL AS p_any_aws_instance_ids,NULL AS p_any_aws_tags,p_any_domain_names,p_any_ip_addresses,p_any_md5_hashes,p_any_sha1_hashes,p_any_sha256_hashes,p_event_time,p_log_type,p_parse_time,p_row_id,p_source_id,p_source_label,year from panther_logs.table1
	union all
select day,hour,month,p_any_aws_account_ids,p_any_aws_arns,p_any_aws_instance_ids,p_any_aws_tags,p_any_domain_names,p_any_ip_addresses,p_any_md5_hashes,p_any_sha1_hashes,p_any_sha256_hashes,p_event_time,p_log_type,p_parse_time,p_row_id,p_source_id,p_source_label,year from panther_logs.table2
;
`
	sql, err := generateViewAllLogs([]*awsglue.GlueTableMetadata{table1, table2})
	require.NoError(t, err)
	require.Equal(t, expectedSQL, sql)
}

func TestGenerateViewAllLogsFail(t *testing.T) {
	// one has daily partitions and one has hourly
	table1 := awsglue.NewGlueTableMetadata(pantherdb.LogData, "table1", "test table1", awsglue.GlueTableDaily, &table1Event{})
	table2 := awsglue.NewGlueTableMetadata(pantherdb.LogData, "table2", "test table2", awsglue.GlueTableHourly, &table2Event{})
	_, err := generateViewAllLogs([]*awsglue.GlueTableMetadata{table1, table2})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "all tables do not share same partition keys"))
}

func TestGenerateLogsViewsFail(t *testing.T) {
	// no tables
	_, err := GenerateLogViews([]*awsglue.GlueTableMetadata{})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "no tables"))
}
