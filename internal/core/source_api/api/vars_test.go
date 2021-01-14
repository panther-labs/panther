package api

import (
	"testing"

	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/testutils"
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
	testIntegrationID    = "45be7365-688f-4c6f-a4da-803be356e3c7"
	testIntegrationLabel = "ProdAWS"
	testAccountID        = "123456789012"
	testUserID           = "97c4db4e-61d5-40a7-82de-6dd63b199bd2"
)

type APITest struct {
	API
	mockDdb    *testutils.DynamoDBMock
	mockSqs    *testutils.SqsMock
	mockS3     *testutils.S3Mock
	mockLambda *testutils.LambdaMock
}

func NewAPITest() *APITest {
	mockDdb := &testutils.DynamoDBMock{}
	mockSqs := &testutils.SqsMock{}
	mockS3 := &testutils.S3Mock{}
	mockLambda := &testutils.LambdaMock{}
	return &APITest{
		mockDdb:    mockDdb,
		mockSqs:    mockSqs,
		mockS3:     mockS3,
		mockLambda: mockLambda,
		API: API{
			SqsClient:        mockSqs,
			LambdaClient:     mockLambda,
			TemplateS3Client: mockS3,
			DdbClient:        &ddb.DDB{TableName: "test", Client: mockDdb},
		},
	}
}

func (a *APITest) AssertExpectations(t *testing.T) {
	a.mockDdb.AssertExpectations(t)
	a.mockS3.AssertExpectations(t)
	a.mockSqs.AssertExpectations(t)
	a.mockLambda.AssertExpectations(t)
}
