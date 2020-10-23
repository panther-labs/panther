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
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	analysisapi "github.com/panther-labs/panther/api/gateway/analysis/client"
	resourceapi "github.com/panther-labs/panther/api/gateway/resources/client"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	maxBackoff = 30 * time.Second
)

type envConfig struct {
	AlertQueueURL   string `required:"true" split_words:"true"`
	AnalysisAPIHost string `required:"true" split_words:"true"`
	AnalysisAPIPath string `required:"true" split_words:"true"`
	PolicyEngine    string `required:"true" split_words:"true"`
	ResourceAPIHost string `required:"true" split_words:"true"`
	ResourceAPIPath string `required:"true" split_words:"true"`
}

var (
	env envConfig

	awsSession       *session.Session
	lambdaClient     lambdaiface.LambdaAPI
	sqsClient        sqsiface.SQSAPI
	complianceClient gatewayapi.API

	httpClient     *http.Client
	analysisClient *analysisapi.PantherAnalysisAPI
	resourceClient *resourceapi.PantherResourcesAPI
)

// Setup parses the environment and initializes AWS and API clients.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	lambdaClient = lambda.New(awsSession)
	sqsClient = sqs.New(awsSession)
	complianceClient = gatewayapi.NewClient(lambdaClient, "panther-compliance-api", nil)

	httpClient = gatewayapi.GatewayClient(awsSession)
	analysisClient = analysisapi.NewHTTPClientWithConfig(
		nil, analysisapi.DefaultTransportConfig().
			WithHost(env.AnalysisAPIHost).WithBasePath("/"+env.AnalysisAPIPath))
	resourceClient = resourceapi.NewHTTPClientWithConfig(
		nil, resourceapi.DefaultTransportConfig().
			WithHost(env.ResourceAPIHost).WithBasePath("/"+env.ResourceAPIPath))
}
