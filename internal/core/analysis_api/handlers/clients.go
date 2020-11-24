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
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	env envConfig

	awsSession       *session.Session
	dynamoClient     dynamodbiface.DynamoDBAPI
	s3Client         s3iface.S3API
	sqsClient        sqsiface.SQSAPI
	complianceClient gatewayapi.API

	policyEngine analysis.PolicyEngine
	ruleEngine   analysis.RuleEngine
)

type envConfig struct {
	Bucket               string `required:"true" split_words:"true"`
	LayerManagerQueueURL string `required:"true" split_words:"true"`
	RulesEngine          string `required:"true" split_words:"true"`
	PolicyEngine         string `required:"true" split_words:"true"`
	ResourceQueueURL     string `required:"true" split_words:"true"`
	Table                string `required:"true" split_words:"true"`
}

// API defines all of the handlers as receiver functions.
type API struct{}

// Setup parses the environment and constructs AWS and http clients on a cold Lambda start.
// All required environment variables must be present or this function will panic.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	dynamoClient = dynamodb.New(awsSession)
	s3Client = s3.New(awsSession)
	sqsClient = sqs.New(awsSession)
	lambdaClient := lambda.New(awsSession)
	complianceClient = gatewayapi.NewClient(lambdaClient, "panther-compliance-api")

	policyEngine = analysis.NewPolicyEngine(lambdaClient, env.PolicyEngine)
	ruleEngine = analysis.NewRuleEngine(lambdaClient, env.RulesEngine)
}
