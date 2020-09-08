package config

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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/firehose/firehoseiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/kelseyhightower/envconfig"
)

var (
	Env            EnvConfig
	AwsSession     *session.Session
	FirehoseClient firehoseiface.FirehoseAPI
	LambdaClient   lambdaiface.LambdaAPI

	MaxRetries = 10
)

const (
	SourceAPIFunctionName = "panther-source-api"
)

type EnvConfig struct {
	StreamName string `required:"true" split_words:"true"`
}

// Setup parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &Env)
	AwsSession = session.Must(session.NewSession(aws.NewConfig().WithMaxRetries(MaxRetries)))

	FirehoseClient = firehose.New(AwsSession)
	LambdaClient = lambda.New(AwsSession)
}
