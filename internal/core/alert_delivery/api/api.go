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
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
	alertTable "github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

// API has all of the handlers as receiver methods.
type API struct{}

type envConfig struct {
	AlertRetryCount           int    `required:"true" split_words:"true"`
	OutputsRefreshIntervalSec int    `required:"true" split_words:"true"`
	MinRetryDelaySecs         int    `required:"true" split_words:"true"`
	MaxRetryDelaySecs         int    `required:"true" split_words:"true"`
	AlertsTableName           string `required:"true" split_words:"true"`
	RuleIndexName             string `required:"true" split_words:"true"`
	TimeIndexName             string `required:"true" split_words:"true"`
	AlertQueueURL             string `required:"true" split_words:"true"`
	AlertsAPI                 string `required:"true" split_words:"true"`
	OutputsAPI                string `required:"true" split_words:"true"`
}

// Globals
var (
	env                    envConfig
	maxRetryCount          int
	outputsRefreshInterval time.Duration
	minRetryDelaySecs      int
	maxRetryDelaySecs      int
	alertQueueURL          string
	alertsAPI              string
	outputsAPI             string
	awsSession             *session.Session
	alertsTableClient      *alertTable.AlertsTable
	lambdaClient           lambdaiface.LambdaAPI
	outputClient           outputs.API
	sqsClient              sqsiface.SQSAPI
	outputsCache           *alertOutputsCache
)

// Setup - parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &env)
	maxRetryCount = env.AlertRetryCount
	outputsRefreshInterval = time.Duration(env.OutputsRefreshIntervalSec) * time.Second
	minRetryDelaySecs = env.MinRetryDelaySecs
	maxRetryDelaySecs = env.MaxRetryDelaySecs
	alertQueueURL = env.AlertQueueURL
	alertsAPI = env.AlertsAPI
	outputsAPI = env.OutputsAPI
	awsSession = session.Must(session.NewSession())
	lambdaClient = lambda.New(awsSession)
	outputClient = outputs.New(awsSession)
	sqsClient = sqs.New(awsSession)
	outputsCache = &alertOutputsCache{}
	alertsTableClient = &alertTable.AlertsTable{
		AlertsTableName:                    env.AlertsTableName,
		Client:                             dynamodb.New(awsSession),
		RuleIDCreationTimeIndexName:        env.RuleIndexName,
		TimePartitionCreationTimeIndexName: env.TimeIndexName,
	}
}
