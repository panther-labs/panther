package compaction

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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/glue"
)

const (
	maxCompactionRetries = 5 // how many times we re-try compacting on error

	ctasDatabase    = "panther_temp" // create temp tables here and delete when done
	ctasSQLTemplate = `
create table %s
with (
  external_location='s3://%s/%s/%s/year=%d/month=%02d/day=%02d/hour=%02d/%s/',
  format='PARQUET', parquet_compression='UNCOMPRESSED'
)
as 
select 
%s
FROM "%s"."%s" where year=%d and month=%d and day=%d and hour=%d order by p_event_time
`
)

func GenerateParquet(databaseName, tableName, bucketName string, hour time.Time) (workflowID string, err error) {
	// get the table schema to collect the columns

	// generate CTAS sql

	// execute CTAS through the Athena API Step Function (non-blocking)

	return workflowID, nil
}

func generateCtasSQL(databaseName, tableType, tableName, bucketName string, columns []*glue.Column,
	hour time.Time, tag string) (tempTable, ctsa string) {

	// generate name for table, by using this key it will fail if another is tried concurrently
	tempTable = ctasDatabase + "." + databaseName + "_" + tableType + "_" + tableName + "_" + hour.Format("2006010215")

	// generate a "tag" for the results folder, VERY IMPORTANT, this allows us to repeat without over writing results
	// tag := uuid.New().String()

	// list the columns
	selectCols := make([]string, len(columns))
	for i := range columns {
		selectCols[i] = *columns[i].Name
	}

	return tempTable, fmt.Sprintf(ctasSQLTemplate,
		tempTable,
		bucketName, tableType, tableName, hour.Year(), hour.Month(), hour.Day(), hour.Hour(), tag,
		strings.Join(selectCols, ","),
		databaseName, tableName, hour.Year(), hour.Month(), hour.Day(), hour.Hour(),
	)
}
