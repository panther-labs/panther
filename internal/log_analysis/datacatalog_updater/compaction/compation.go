package compaction

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

import "time"

const (
	ctasSQLTemplate = `
create table panther_temp.%s
with (
  external_location='s3://%s/%s/%s/year=%0d/month=%0d/day=%0d/hour=%0d/',
  format='PARQUET', parquet_compression='UNCOMPRESSED'
)
as 
select 
%s
FROM "%s"."%s" where year=%d and month=%d and day=%d and hour=%d order by p_event_time
`
)

func GenerateCtasSQL(databaseName, tableName, bucketName string, hour time.Time) (ctas string, err error) {
	return ctas, err
}
