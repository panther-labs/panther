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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
)

const (
	LambdaName = "panther-source-api"

	templateBucketRegion = endpoints.UsWest2RegionID
)

type Config struct {
	AccountID                  string `required:"true" split_words:"true"`
	AWSPartition               string `required:"true" envconfig:"aws_partition"`
	DataCatalogUpdaterQueueURL string `required:"true" split_words:"true"`
	Debug                      bool   `required:"false"`
	LogProcessorQueueURL       string `required:"true" split_words:"true"`
	LogProcessorQueueArn       string `required:"true" split_words:"true"`
	InputDataRoleArn           string `required:"true" split_words:"true"`
	InputDataBucketName        string `required:"true" split_words:"true"`
	InputDataTopicArn          string `required:"true" split_words:"true"`
	SnapshotPollersQueueURL    string `required:"true" split_words:"true"`
	TableName                  string `required:"true" split_words:"true"`
	Version                    string `required:"true" split_words:"true"`
	// this is not populated by Env variables
	Region string
}

// Setup parses the environment and constructs AWS and http clients on a cold Lambda start.
// All required environment variables must be present or this function will panic.
func Setup() *API {
	var env Config
	envconfig.MustProcess("", &env)
	awsSession := session.Must(session.NewSession())
	env.Region = aws.StringValue(awsSession.Config.Region)
	api := &API{
		AwsSession:       awsSession,
		DdbClient:        ddb.New(awsSession, env.TableName),
		SqsClient:        sqs.New(awsSession),
		TemplateS3Client: s3.New(awsSession, aws.NewConfig().WithRegion(templateBucketRegion)),
		LambdaClient:     lambda.New(awsSession),
		Config:           env,
	}
	api.EvaluateIntegrationFunc = api.evaluateIntegration
	return api
}

// API provides receiver methods for each route handler.
type API struct {
	AwsSession              *session.Session
	DdbClient               *ddb.DDB
	SqsClient               sqsiface.SQSAPI
	TemplateS3Client        s3iface.S3API
	LambdaClient            lambdaiface.LambdaAPI
	Config                  Config
	EvaluateIntegrationFunc func(integration *models.CheckIntegrationInput) (string, bool, error)
}
