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
	"os"

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
)

var (
	awsSession          *session.Session
	glueClient          glueiface.GlueAPI
	athenaClient        athenaiface.AthenaAPI
	lambdaClient        lambdaiface.LambdaAPI
	sfnClient           sfniface.SFNAPI
	s3Client            s3iface.S3API
	athenaS3ResultsPath *string
	pantherTablesOnly   bool // if true, for Glue  APIs, only return to users tables from Panther databases
)

func SessionInit() {
	awsSession = session.Must(session.NewSession())
	glueClient = glue.New(awsSession)
	athenaClient = athena.New(awsSession)
	lambdaClient = lambda.New(awsSession)
	sfnClient = sfn.New(awsSession)
	s3Client = s3.New(awsSession)
	if os.Getenv("ATHENA_BUCKET") != "" {
		results := "s3://" + os.Getenv("ATHENA_BUCKET") + "/athena_api/"
		athenaS3ResultsPath = &results
	}
	pantherTablesOnly = os.Getenv("PANTHER_TABLES_ONLY") == "true"
}

// API provides receiver methods for each route handler.
type API struct{}
