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
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/aws/aws-sdk-go/service/sfn/sfniface"
	"github.com/kelseyhightower/envconfig"
)

var (
	awsSession   *session.Session
	glueClient   glueiface.GlueAPI
	athenaClient athenaiface.AthenaAPI
	lambdaClient lambdaiface.LambdaAPI
	sfnClient    sfniface.SFNAPI
	s3Client     s3iface.S3API

	envConfig           EnvConfig
	athenaS3ResultsPath *string
)

type EnvConfig struct {
	AthenaStatemachineARN string `required:"true" split_words:"true"`
	AthenaBucket          string `default:"" split_words:"true"`
	GraphqlEndpoint       string `required:"true" split_words:"true"`
	PantherTablesOnly     bool   `default:"false" split_words:"true"` // if true, only return tables from Panther databases
}

func SessionInit() {
	awsSession = session.Must(session.NewSession())
	glueClient = glue.New(awsSession)
	athenaClient = athena.New(awsSession)
	lambdaClient = lambda.New(awsSession)
	sfnClient = sfn.New(awsSession)
	s3Client = s3.New(awsSession)

	err := envconfig.Process("", &envConfig)
	if err != nil {
		panic(err)
	}
	if envConfig.AthenaBucket != "" {
		results := "s3://" + envConfig.AthenaBucket + "/athena_api/"
		athenaS3ResultsPath = &results
	}
}

// API provides receiver methods for each route handler.
type API struct{}
