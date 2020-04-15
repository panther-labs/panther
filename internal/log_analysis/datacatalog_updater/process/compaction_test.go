package process

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
)

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

const (
	testBucket   = "testBucket"
	testDb       = "panther_logs"
	tableType    = "logs"
	tableName    = "aws_cloudtrail"
	executionTag = "1234"
)

func TestGenerateCtasSQL(t *testing.T) {
	refTime := time.Date(2020, 4, 10, 5, 0, 0, 0, time.UTC)
	expectedSQL := `
create table panther_temp.panther_logs_aws_cloudtrail_2020041005
with (
  external_location='s3://testBucket/logs/aws_cloudtrail/year=2020/month=04/day=10/hour=05/1234/',
  format='PARQUET', parquet_compression='UNCOMPRESSED'
)
as 
select 
c1,c2
FROM "panther_logs"."aws_cloudtrail" where year=2020 and month=4 and day=10 and hour=5 order by p_event_time
`
	cols := []*glue.Column{
		{Name: aws.String("c1")},
		{Name: aws.String("c2")},
	}
	sql := generateCtasSQL(testDb, tableType, tableName, testBucket, cols, refTime, executionTag)
	assert.Equal(t, expectedSQL, sql)
}
