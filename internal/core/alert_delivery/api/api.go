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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/utils"
)

// API has all of the handlers as receiver methods.
type API struct{}

var (
	env        envConfig
	awsSession = session.Must(session.NewSession())
	alertsDB   table.API
	alertUtils utils.API
	// We need the Lambda client for the following:
	//  1. To fetch the details from the destination outputs
	//  2. To get the rule or policy associated with the original alert (for re-sending alerts)
	//  3. To invoke the Alerts API lambda to up date the delivery status
	lambdaClient lambdaiface.LambdaAPI = lambda.New(awsSession)
	outputClient outputs.API           = outputs.New(awsSession)

	// Lazy-load the SQS client - we only need it to retry failed alerts
	sqsClient sqsiface.SQSAPI
)

type envConfig struct {
	AlertsTableName string `required:"true" split_words:"true"`
	RuleIndexName   string `required:"true" split_words:"true"`
	TimeIndexName   string `required:"true" split_words:"true"`
}

// Setup - parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &env)
	alertsDB = &table.AlertsTable{
		AlertsTableName:                    env.AlertsTableName,
		Client:                             dynamodb.New(awsSession),
		RuleIDCreationTimeIndexName:        env.RuleIndexName,
		TimePartitionCreationTimeIndexName: env.TimeIndexName,
	}
	alertUtils = &utils.AlertUtils{}
}

func getSQSClient() sqsiface.SQSAPI {
	if sqsClient == nil {
		sqsClient = sqs.New(awsSession)
	}
	return sqsClient
}
