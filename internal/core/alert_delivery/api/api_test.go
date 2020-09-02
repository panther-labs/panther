package api

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
	"os"

	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/mock"
)

type mockLambdaClient struct {
	lambdaiface.LambdaAPI
	mock.Mock
}

func (m *mockLambdaClient) Invoke(input *lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*lambda.InvokeOutput), args.Error(1)
}

type mockSQSClient struct {
	sqsiface.SQSAPI
	mock.Mock
}

func (m *mockSQSClient) SendMessageBatch(input *sqs.SendMessageBatchInput) (*sqs.SendMessageBatchOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SendMessageBatchOutput), args.Error(1)
}

func initEnvironmentTest() {
	os.Setenv("ALERT_RETRY_COUNT", "10")
	os.Setenv("OUTPUTS_REFRESH_INTERVAL", "30s")
	os.Setenv("MIN_RETRY_DELAY_SECS", "10")
	os.Setenv("MAX_RETRY_DELAY_SECS", "30")
	os.Setenv("ALERT_QUEUE_URL", "sqs-url")
	os.Setenv("ALERTS_API", "alerts-api")
	os.Setenv("OUTPUTS_API", "outputs-api")
	os.Setenv("ALERTS_TABLE_NAME", "alerts-table-name")
	os.Setenv("RULE_INDEX_NAME", "rule-index")
	os.Setenv("TIME_INDEX_NAME", "time-index")
	os.Setenv("ANALYSIS_API_HOST", "analysis-api-host")
	os.Setenv("ANALYSIS_API_PATH", "v1")
	Setup()
}
