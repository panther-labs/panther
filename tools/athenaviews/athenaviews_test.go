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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/awsglue"
)

func TestGenerateViewAllLogs(t *testing.T) {
	table, err := awsglue.NewGlueMetadata("db", "table1", "test table", awsglue.GlueTableHourly,
		false, nil)
	require.NoError(t, err)
	expectedSQL := "create or replace view panther_views.all_logs as\nselect p_log_type,p_row_id,p_event_time,p_any_ip_addresses,p_any_ip_domain_names,p_any_aws_account_ids,p_any_aws_instance_ids,p_any_aws_arns,p_any_aws_tags,year,month,day,hour from db.table1\n;\n" // nolint (lll)
	require.Equal(t, expectedSQL, generateViewAllLogs([]*awsglue.GlueMetadata{table}))
}
