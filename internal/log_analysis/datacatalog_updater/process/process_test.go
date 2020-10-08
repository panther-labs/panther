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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestProcessSuccess(t *testing.T) {
	initProcessTest()

	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockGlueClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil).Once()

	assert.NoError(t, handleSQSEvent(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz")))
	mockGlueClient.AssertExpectations(t)
}

func TestProcessSuccessAlreadyCreatedPartition(t *testing.T) {
	initProcessTest()

	// We should attempt to create the partition only once. We shouldn't try to re-create it a second time
	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockGlueClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil).Once()

	// First object should invoke Glue API
	assert.NoError(t, handleSQSEvent(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz")))
	// Second object is in the same partition as the first one. It shouldn't invoke the Glue API since the partition is already created.
	assert.NoError(t, handleSQSEvent(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/new_item.json.gz")))
	mockGlueClient.AssertExpectations(t)
}

func TestProcessSuccessDontPopulateCacheOnFailure(t *testing.T) {
	initProcessTest()

	// First glue operation fails
	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockGlueClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, errors.New("createPartitionError")).Once()

	// Second glue operation succeeds
	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockGlueClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil).Once()

	// First invocation fails
	assert.Error(t, handleSQSEvent(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz")))
	// Second invocation succeeds
	assert.NoError(t, handleSQSEvent(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz")))
	mockGlueClient.AssertExpectations(t)
}

func TestProcessGlueFailure(t *testing.T) {
	initProcessTest()

	mockGlueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockGlueClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, errors.New("error")).Once()

	assert.Error(t, handleSQSEvent(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz")))
	mockGlueClient.AssertExpectations(t)
}

func TestProcessInvalidS3Key(t *testing.T) {
	initProcessTest()
	//Invalid keys should just be ignored
	assert.NoError(t, handleSQSEvent(getEvent(t, "test")))
}

// initProcessTest is run at the start of each test to create new mocks and reset state
func initProcessTest() {
	partitionPrefixCache = make(map[string]struct{})
	mockGlueClient = &testutils.GlueMock{}
	glueClient = mockGlueClient
}
