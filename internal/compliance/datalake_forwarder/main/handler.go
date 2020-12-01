package main

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
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/firehose"
	lambdaservice "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder"
	"github.com/panther-labs/panther/pkg/awsretry"
)

func main() {
	lambda.Start(NewHandler().Run)
}

type EnvConfig struct {
	StreamName string `required:"true" split_words:"true"`
}

func NewHandler() *forwarder.StreamHandler {
	var config EnvConfig
	envconfig.MustProcess("", &config)

	const maxRetries = 10
	awsSession := session.Must(session.NewSession(request.WithRetryer(aws.NewConfig().WithMaxRetries(maxRetries),
		awsretry.NewConnectionErrRetryer(maxRetries))))
	firehoseClient := firehose.New(awsSession)
	lambdaClient := lambdaservice.New(awsSession)
	return &forwarder.StreamHandler{
		LambdaClient:   lambdaClient,
		FirehoseClient: firehoseClient,
		StreamName:     config.StreamName,
	}
}
