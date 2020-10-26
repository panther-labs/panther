package gluetables

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	refTime = time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)

	testColumns = []*glue.Column{
		{
			Name: aws.String("col1"),
			Type: aws.String("int"),
		},
	}

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
			CreateTime:        aws.Time(refTime),
			StorageDescriptor: testStorageDescriptor,
		},
	}
)

func TestDeployedTablesSignature(t *testing.T) {
	mockGlueClient := &testutils.GlueMock{}
	numLogTables := len(registry.AvailableTables())

	// return the same dummy table for all tables
	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Times(numLogTables)
	sig, err := DeployedTablesSignature(mockGlueClient)
	require.NoError(t, err)

	// do it again on original tables, they should be the same
	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Times(numLogTables)
	sig2, err := DeployedTablesSignature(mockGlueClient)
	require.NoError(t, err)
	assert.Equal(t, sig, sig2)

	// change the data, the sigs should be different
	require.NoError(t, registry.Register(logtypes.MustBuild(logtypes.Config{
		Name:         "Foo.Bar",
		Description:  "foo",
		ReferenceURL: "-",
		Schema: struct {
			Foo string `json:"foo" description:"bar"`
		}{},
		NewParser: parsers.FactoryFunc(func(_ interface{}) (parsers.Interface, error) {
			return nil, nil
		}),
	})))
	defer registry.Del("Foo.Bar")
	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Times(numLogTables + 1)
	modifiedSig, err := DeployedTablesSignature(mockGlueClient)
	require.NoError(t, err)
	assert.NotEqual(t, sig, modifiedSig)

	mockGlueClient.AssertExpectations(t)
}
