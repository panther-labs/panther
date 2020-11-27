package awsglue

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
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/core/pantherdb"
)

// Meta data about GlueTableMetadata table over parser data written to S3
// NOTE: this struct has all accessor behind functions to allow a lazy evaluation
//       so the cost of creating the schema is only when actually needing this information.

// A partition in Glue containing Panther data
type GluePartition struct {
	databaseName     string
	tableName        string
	s3Bucket         string
	time             time.Time // the time (e.g., specific hour) this partition corresponds to
	partitionColumns []PartitionColumnInfo
	gm               *GlueTableMetadata // this is the abstraction for dealing directly with the glue catalog
}

func (gp *GluePartition) GetDatabase() string {
	return gp.databaseName
}

func (gp *GluePartition) GetTable() string {
	return gp.tableName
}

func (gp *GluePartition) GetTime() time.Time {
	return gp.time
}

func (gp *GluePartition) GetS3Bucket() string {
	return gp.s3Bucket
}

func (gp *GluePartition) GetPartitionColumnsInfo() []PartitionColumnInfo {
	return gp.partitionColumns
}

func (gp *GluePartition) GetGlueTableMetadata() *GlueTableMetadata {
	return gp.gm
}

func GetPartitionPrefix(database, logType string, timebin GlueTableTimebin, time time.Time) string {
	return getTablePrefix(database, pantherdb.GetTable(logType)) + timebin.PartitionPathS3(time)
}

func (gp *GluePartition) GetPartitionLocation() string {
	return "s3://" + gp.s3Bucket + "/" + gp.gm.GetPartitionPrefix(gp.time)
}

// GetPartitionLocation takes an S3 path for an object and returns just the part of the patch associated with the partition
func GetPartitionLocation(s3Path string) (string, error) {
	gluePartition, err := GetPartitionFromS3Path(s3Path)
	if err != nil {
		return "", errors.Wrapf(err, "cannot parse partition path %s", s3Path)
	}
	return gluePartition.GetPartitionLocation(), nil
}

// Contains information about partition columns
type PartitionColumnInfo struct {
	Key   string
	Value string
}

// Gets the partition from S3bucket and S3 object key info.
// The s3Object key is expected to be in the the format
// `{logs,rules}/{table_name}/year=d{4}/month=d{2}/[day=d{2}/][hour=d{2}/]/{S+}.json.gz` otherwise an error is returned.
func GetPartitionFromS3(s3Bucket, s3ObjectKey string) (*GluePartition, error) {
	partition := &GluePartition{s3Bucket: s3Bucket}

	s3Keys := strings.Split(s3ObjectKey, "/")
	if len(s3Keys) < 4 {
		return nil, errors.Errorf("s3 object key [%s] doesn't have the appropriate format", s3ObjectKey)
	}

	switch s3Keys[0] {
	case logS3Prefix:
		partition.databaseName = pantherdb.LogProcessingDatabase
	case ruleMatchS3Prefix:
		partition.databaseName = pantherdb.RuleMatchDatabase
	case ruleErrorsS3Prefix:
		partition.databaseName = pantherdb.RuleErrorsDatabase
	case cloudsecurityS3Prefix:
		partition.databaseName = pantherdb.CloudSecurityDatabase
	default:
		return nil, errors.Errorf("unsupported S3 object prefix %s from %s", s3Keys[0], s3ObjectKey)
	}

	partition.tableName = s3Keys[1]

	yearPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[2], "year")
	if err != nil {
		return nil, err
	}

	partition.partitionColumns = []PartitionColumnInfo{yearPartitionKeyValue}

	monthPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[3], "month")
	if err != nil {
		return nil, err
	}

	partition.partitionColumns = append(partition.partitionColumns, monthPartitionKeyValue)
	if len(s3Keys) == 4 {
		// if there are no more fields, stop here
		return partition, nil
	}

	dayPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[4], "day")
	if err != nil {
		return partition, nil
	}
	partition.partitionColumns = append(partition.partitionColumns, dayPartitionKeyValue)
	if len(s3Keys) == 5 {
		return partition, nil
	}

	hourPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[5], "hour")
	if err != nil {
		return partition, nil
	}
	partition.partitionColumns = append(partition.partitionColumns, hourPartitionKeyValue)

	// add partition.hour as time.Time
	year, err := strconv.Atoi(yearPartitionKeyValue.Value)
	if err != nil {
		return partition, nil
	}
	month, err := strconv.Atoi(monthPartitionKeyValue.Value)
	if err != nil {
		return partition, nil
	}
	day, err := strconv.Atoi(dayPartitionKeyValue.Value)
	if err != nil {
		return partition, nil
	}
	hour, err := strconv.Atoi(hourPartitionKeyValue.Value)
	if err != nil {
		return partition, nil
	}
	partition.time = time.Date(year, time.Month(month), day, hour, 0, 0, 0, time.UTC)

	partition.gm = NewGlueTableMetadata(partition.databaseName, partition.tableName, "", GlueTableHourly, nil)

	return partition, nil
}

func GetPartitionFromS3Path(s3Path string) (*GluePartition, error) {
	bucketName, key, err := ParseS3URL(s3Path)
	if err != nil {
		return nil, err
	}
	return GetPartitionFromS3(bucketName, key)
}

func inferPartitionColumnInfo(input string, partitionName string) (PartitionColumnInfo, error) {
	fields := strings.Split(input, "=")
	if len(fields) != 2 || fields[0] != partitionName {
		return PartitionColumnInfo{}, errors.Errorf("failed to get partition key %s from %s", partitionName, input)
	}

	_, err := strconv.Atoi(fields[1])
	if err != nil {
		return PartitionColumnInfo{}, errors.Wrapf(err, "failed to parse to integer %s", fields[1])
	}
	return PartitionColumnInfo{Key: partitionName, Value: fields[1]}, nil
}
