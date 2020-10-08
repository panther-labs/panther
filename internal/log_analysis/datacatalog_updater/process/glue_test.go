package process

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
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	mockGlueClient *testutils.GlueMock

	// dummy data for columns
	testColumns = []*glue.Column{
		{
			Name: aws.String("col"),
			Type: aws.String("int"),
		},
	}

	// the important thing here is that this of type JSON
	testStorageDescriptor = &glue.StorageDescriptor{
		Columns:  testColumns,
		Location: aws.String("s3://testbucket/logs/table"),
		SerdeInfo: &glue.SerDeInfo{
			SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
			Parameters: map[string]*string{
				"serialization.format": aws.String("1"),
				"case.insensitive":     aws.String("TRUE"),
			},
		},
	}

	testGetTableOutput = &glue.GetTableOutput{
		Table: &glue.TableData{
			StorageDescriptor: testStorageDescriptor,
		},
	}
)

func getEvent(t *testing.T, s3Keys ...string) events.SQSEvent {
	result := events.SQSEvent{Records: []events.SQSMessage{}}
	for _, s3Key := range s3Keys {
		s3Notification := NewS3ObjectPutNotification("bucket", s3Key, 0)
		serialized, err := jsoniter.MarshalToString(s3Notification)
		require.NoError(t, err)
		event := events.SQSMessage{
			Body: serialized,
		}
		result.Records = append(result.Records, event)
	}
	return result
}
