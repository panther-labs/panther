package process

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
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/pkg/awsretry"
)

const (
	maxRetries = 20 // setting Max Retries to a higher number - we'd like to retry VERY hard before failing.
)

var (
	config = struct {
		SyncWorkersPerTable int    `default:"10" split_words:"true"`
		ProcessedDataBucket string `split_words:"true"`
	}{}
	awsSession   *session.Session
	glueClient   glueiface.GlueAPI
	lambdaClient lambdaiface.LambdaAPI
	athenaClient athenaiface.AthenaAPI
)

func Setup() {
	envconfig.MustProcess("", &config)
	awsSession = session.Must(session.NewSession(request.WithRetryer(aws.NewConfig().WithMaxRetries(maxRetries),
		awsretry.NewConnectionErrRetryer(maxRetries))))
	glueClient = glue.New(awsSession)
	lambdaClient = lambda.New(awsSession)
	athenaClient = athena.New(awsSession)
}
