package processor

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
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	maxBackoff = 30 * time.Second
)

type envConfig struct {
	AlertQueueURL string `required:"true" split_words:"true"`
	PolicyEngine  string `required:"true" split_words:"true"`
}

var (
	env envConfig

	awsSession       *session.Session
	lambdaClient     lambdaiface.LambdaAPI
	sqsClient        sqsiface.SQSAPI
	analysisClient   gatewayapi.API
	complianceClient gatewayapi.API
	resourceClient   gatewayapi.API
)

// Setup parses the environment and initializes AWS and API clients.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	lambdaClient = lambda.New(awsSession)
	sqsClient = sqs.New(awsSession)
	analysisClient = gatewayapi.NewClient(lambdaClient, "panther-analysis-api")
	complianceClient = gatewayapi.NewClient(lambdaClient, "panther-compliance-api")
	resourceClient = gatewayapi.NewClient(lambdaClient, "panther-resources-api")
}
