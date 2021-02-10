package handlers

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
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type envConfig struct {
	ResourcesQueueURL string `required:"true" split_words:"true"`
	ResourcesTable    string `required:"true" split_words:"true"`
	ScanSegments      int    `required:"true" split_words:"true"`
}

// API has all of the handlers as receiver methods.
type API struct{}

var (
	env envConfig

	awsSession       *session.Session
	dynamoClient     dynamodbiface.DynamoDBAPI
	sqsClient        sqsiface.SQSAPI
	complianceClient gatewayapi.API
)

// Setup parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	dynamoClient = dynamodb.New(awsSession)
	sqsClient = sqs.New(awsSession)
	complianceClient = gatewayapi.NewClient(lambda.New(awsSession), "panther-compliance-api")
}
