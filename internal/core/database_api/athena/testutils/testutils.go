package testutils

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
)

/*
	This file has functions to create a bucket and a Panther JSON table, populated with a small amount of data.
	There are also functions to clean up after running the tests.

	This can be used to drive Athena API related integration tests for packages that need example data.
*/

const (
	TestBucketPrefix = "panther-athena-api-processeddata-test-"
	TestDb           = "panther_athena_api_test_db"
	TestTable        = "panther_athena_test_table"
)

var (
	TestBucket string

	TestPartitionTime = time.Date(2020, 3, 2, 1, 0, 0, 0, time.UTC)

	TestYear  = fmt.Sprintf("%d", TestPartitionTime.Year())
	TestMonth = fmt.Sprintf("%02d", TestPartitionTime.Month())
	TestDay   = fmt.Sprintf("%02d", TestPartitionTime.Day())
	TestHour  = fmt.Sprintf("%02d", TestPartitionTime.Hour())

	TestEventTime = TestPartitionTime.Format(`2006-01-02 15:04:05.000`)

	TestTableColumns = []*glue.Column{
		{
			Name:    aws.String("col1"),
			Type:    aws.String("int"),
			Comment: aws.String("this is a column"),
		},
		{
			Name:    aws.String("col2"),
			Type:    aws.String("int"),
			Comment: aws.String("this is a column"),
		},
		{
			Name:    aws.String("p_event_time"),
			Type:    aws.String("timestamp"),
			Comment: aws.String("this is a panther column"),
		},
	}

	YearPartitionName  = "year"
	MonthPartitionName = "month"
	DayPartitionName   = "day"
	HourPartitionName  = "hour"

	TestTablePartitions = []*glue.Column{
		{
			Name:    aws.String(YearPartitionName),
			Type:    aws.String("int"),
			Comment: aws.String("this is the year"),
		},
		{
			Name:    aws.String(MonthPartitionName),
			Type:    aws.String("int"),
			Comment: aws.String("this is the month"),
		},
		{
			Name:    aws.String(DayPartitionName),
			Type:    aws.String("int"),
			Comment: aws.String("this is the day"),
		},
		{
			Name:    aws.String(HourPartitionName),
			Type:    aws.String("int"),
			Comment: aws.String("this is the hour"),
		},
	}

	TestKey string

	TestTableDataNrows   = 10
	TestTableRowTemplate = `{"col1": %d, "col2": null, "p_event_time": "%s"}`
	TestTableRows        []string
)

func init() {
	TestBucket = TestBucketPrefix + time.Now().Format("20060102150405")

	// make it look like log data
	TestKey = "logs/aws_cloudtrail/"
	TestKey += YearPartitionName + "=" + TestYear + "/"
	TestKey += MonthPartitionName + "=" + TestMonth + "/"
	TestKey += DayPartitionName + "=" + TestDay + "/"
	TestKey += HourPartitionName + "=" + TestHour + "/"
	TestKey += "testdata.json"

	for i := 0; i < TestTableDataNrows; i++ {
		TestTableRows = append(TestTableRows, fmt.Sprintf(TestTableRowTemplate, i, TestEventTime))
	}
}

func CheckTableDetail(t *testing.T, tables []*models.TableDetail) {
	require.Equal(t, TestTable, tables[0].Name)
	require.Equal(t, len(TestTableColumns)+len(TestTablePartitions), len(tables[0].Columns))

	// col1
	require.Equal(t, *TestTableColumns[0].Name, tables[0].Columns[0].Name)
	require.Equal(t, *TestTableColumns[0].Type, tables[0].Columns[0].Type)
	require.Equal(t, *TestTableColumns[0].Comment, *tables[0].Columns[0].Description)

	// col2
	require.Equal(t, *TestTableColumns[1].Name, tables[0].Columns[1].Name)
	require.Equal(t, *TestTableColumns[1].Type, tables[0].Columns[1].Type)
	require.Equal(t, *TestTableColumns[1].Comment, *tables[0].Columns[1].Description)

	// p_event_time
	require.Equal(t, *TestTableColumns[2].Name, tables[0].Columns[2].Name)
	require.Equal(t, *TestTableColumns[2].Type, tables[0].Columns[2].Type)
	require.Equal(t, *TestTableColumns[2].Comment, *tables[0].Columns[2].Description)

	// year
	require.Equal(t, *TestTablePartitions[0].Name, tables[0].Columns[3].Name)
	require.Equal(t, *TestTablePartitions[0].Type, tables[0].Columns[3].Type)
	require.Equal(t, *TestTablePartitions[0].Comment, *tables[0].Columns[3].Description)

	// month
	require.Equal(t, *TestTablePartitions[1].Name, tables[0].Columns[4].Name)
	require.Equal(t, *TestTablePartitions[1].Type, tables[0].Columns[4].Type)
	require.Equal(t, *TestTablePartitions[1].Comment, *tables[0].Columns[4].Description)

	// day
	require.Equal(t, *TestTablePartitions[2].Name, tables[0].Columns[5].Name)
	require.Equal(t, *TestTablePartitions[2].Type, tables[0].Columns[5].Type)
	require.Equal(t, *TestTablePartitions[2].Comment, *tables[0].Columns[5].Description)

	// hour
	require.Equal(t, *TestTablePartitions[3].Name, tables[0].Columns[6].Name)
	require.Equal(t, *TestTablePartitions[3].Type, tables[0].Columns[6].Type)
	require.Equal(t, *TestTablePartitions[3].Comment, *tables[0].Columns[6].Description)
}

func SetupTables(t *testing.T, glueClient glueiface.GlueAPI, s3Client s3iface.S3API) {
	RemoveTables(t, glueClient, s3Client) // in case of left over
	AddTables(t, glueClient, s3Client)
}

func AddTables(t *testing.T, glueClient glueiface.GlueAPI, s3Client s3iface.S3API) {
	var err error

	bucketInput := &s3.CreateBucketInput{Bucket: aws.String(TestBucket)}
	_, err = s3Client.CreateBucket(bucketInput)
	require.NoError(t, err)

	dbInput := &glue.CreateDatabaseInput{
		DatabaseInput: &glue.DatabaseInput{
			Name: aws.String(TestDb),
		},
	}
	_, err = glueClient.CreateDatabase(dbInput)
	require.NoError(t, err)

	storageDecriptor := &glue.StorageDescriptor{ // configure as JSON
		Columns:      TestTableColumns,
		Location:     aws.String("s3://" + TestBucket + "/"),
		InputFormat:  aws.String("org.apache.hadoop.mapred.TextInputFormat"),
		OutputFormat: aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
		SerdeInfo: &glue.SerDeInfo{
			SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
			Parameters: map[string]*string{
				"serialization.format": aws.String("1"),
				"case.insensitive":     aws.String("TRUE"), // treat as lower case
			},
		},
	}

	tableInput := &glue.CreateTableInput{
		DatabaseName: aws.String(TestDb),
		TableInput: &glue.TableInput{
			Name:              aws.String(TestTable),
			PartitionKeys:     TestTablePartitions,
			StorageDescriptor: storageDecriptor,
			TableType:         aws.String("EXTERNAL_TABLE"),
		},
	}
	_, err = glueClient.CreateTable(tableInput)
	require.NoError(t, err)

	putInput := &s3.PutObjectInput{
		Body:   strings.NewReader(strings.Join(TestTableRows, "\n")),
		Bucket: &TestBucket,
		Key:    &TestKey,
	}
	_, err = s3Client.PutObject(putInput)
	require.NoError(t, err)
	time.Sleep(time.Second / 4) // short pause since S3 is eventually consistent

	_, err = glueClient.CreatePartition(&glue.CreatePartitionInput{
		DatabaseName: aws.String(TestDb),
		TableName:    aws.String(TestTable),
		PartitionInput: &glue.PartitionInput{
			StorageDescriptor: storageDecriptor,
			Values: []*string{
				aws.String(TestYear),
				aws.String(TestMonth),
				aws.String(TestDay),
				aws.String(TestHour),
			},
		},
	})
	require.NoError(t, err)
}

func RemoveTables(t *testing.T, glueClient glueiface.GlueAPI, s3Client s3iface.S3API) {
	// best effort, no error checks

	tableInput := &glue.DeleteTableInput{
		DatabaseName: aws.String(TestDb),
		Name:         aws.String(TestTable),
	}
	glueClient.DeleteTable(tableInput) // nolint (errcheck)

	dbInput := &glue.DeleteDatabaseInput{
		Name: aws.String(TestDb),
	}
	glueClient.DeleteDatabase(dbInput) // nolint (errcheck)

	RemoveBucket(s3Client, TestBucket)
}

func RemoveBucket(client s3iface.S3API, bucketName string) {
	input := &s3.ListObjectVersionsInput{Bucket: &bucketName}
	var objectVersions []*s3.ObjectIdentifier

	// List all object versions (including delete markers)
	err := client.ListObjectVersionsPages(input, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
		for _, marker := range page.DeleteMarkers {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: marker.Key, VersionId: marker.VersionId})
		}

		for _, version := range page.Versions {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: version.Key, VersionId: version.VersionId})
		}
		return false
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoSuchBucket" {
			return
		}
	}

	err = s3batch.DeleteObjects(client, 2*time.Minute, &s3.DeleteObjectsInput{
		Bucket: &bucketName,
		Delete: &s3.Delete{Objects: objectVersions},
	})
	if err != nil {
		return
	}
	time.Sleep(time.Second / 4) // short pause since S3 is eventually consistent to avoid next call from failing
	if _, err = client.DeleteBucket(&s3.DeleteBucketInput{Bucket: &bucketName}); err != nil {
		return
	}
}
