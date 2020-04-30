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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/core/source_api/ddb"
)

const (
	maxElapsedTime       = 5 * time.Second
	templateBucketRegion = endpoints.UsWest2RegionID
)

var (
	env        envConfig
	awsSession *session.Session

	dynamoClient     *ddb.DDB
	sqsClient        sqsiface.SQSAPI
	templateS3Client s3iface.S3API
)

type envConfig struct {
	SnapshotPollersQueueURL string `required:"true" split_words:"true"`
	LogProcessorQueueURL    string `required:"true" split_words:"true"`
	LogProcessorQueueArn    string `required:"true" split_words:"true"`
	TableName               string `required:"true" split_words:"true"`
}

// Setup parses the environment and constructs AWS and http clients on a cold Lambda start.
// All required environment variables must be present or this function will panic.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	dynamoClient = ddb.New(env.TableName)
	sqsClient = sqs.New(awsSession)
	templateS3Client = s3.New(awsSession, &aws.Config{
		Region: aws.String(templateBucketRegion),
	})
}

// API provides receiver methods for each route handler.
type API struct{}
