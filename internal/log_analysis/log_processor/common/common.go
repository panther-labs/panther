package common

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
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"
)

const (
	MaxRetries     = 20 // setting Max Retries to a higher number - we'd like to retry VERY hard before failing.
	EventDelimiter = '\n'
)

var (
	// Session and clients that can be used by components of the log processor
	Session      *session.Session
	LambdaClient lambdaiface.LambdaAPI
	S3Uploader   s3manageriface.UploaderAPI
	SqsClient    sqsiface.SQSAPI
	SnsClient    snsiface.SNSAPI

	Config EnvConfig
)

type EnvConfig struct {
	AwsLambdaFunctionMemorySize int    `required:"true" split_words:"true"`
	ProcessedDataBucket         string `required:"true" split_words:"true"`
	SqsQueueURL                 string `required:"true" split_words:"true"`
	SnsTopicARN                 string `required:"true" split_words:"true"`
}

func Setup() {
	Session = session.Must(session.NewSession(aws.NewConfig().WithMaxRetries(MaxRetries)))
	LambdaClient = lambda.New(Session)
	S3Uploader = s3manager.NewUploader(Session)
	SqsClient = sqs.New(Session)
	SnsClient = sns.New(Session)

	err := envconfig.Process("", &Config)
	if err != nil {
		panic(err)
	}
}

// DataStream represents a data stream that read by the processor
type DataStream struct {
	Reader io.Reader
	Hints  DataStreamHints
	// The log type if known
	// If it is nil, it means the log type hasn't been identified yet
	LogType *string
}

// Used in a DataStream as meta data to describe the data
type DataStreamHints struct {
	S3 *S3DataStreamHints // if nil, no hint
}

// Used in a DataStreamHints as meta data to describe the S3 object backing the stream
type S3DataStreamHints struct {
	Bucket      string
	Key         string
	ContentType string
}
