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
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/glue"
	lambdaclient "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/datacatalog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/awsretry"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// The panther-datacatalog-updater lambda is responsible for managing Glue partitions as data is created.

const (
	maxRetries = 20 // setting Max Retries to a higher number - we'd like to retry VERY hard before failing.
)

func main() {
	// nolint: maligned
	config := struct {
		AthenaWorkgroup     string `required:"true" split_words:"true"`
		SyncWorkersPerTable int    `default:"10" split_words:"true"`
		QueueURL            string `required:"true" split_words:"true"`
		ProcessedDataBucket string `split_words:"true"`
		Debug               bool   `split_words:"true"`
	}{}
	envconfig.MustProcess("", &config)

	logger := lambdalogger.Config{
		Debug:     config.Debug,
		Namespace: "log_analysis",
		Component: "datacatalog_updater",
	}.MustBuild()

	// For compatibility in case some part of the code still uses zap.L()
	zap.ReplaceGlobals(logger)

	awsSession := session.Must(session.NewSession()) // use default retries for fetching creds, avoids hangs!
	clientsSession := awsSession.Copy(
		request.WithRetryer(
			aws.NewConfig().WithMaxRetries(maxRetries),
			awsretry.NewConnectionErrRetryer(maxRetries),
		),
	)

	lambdaClient := lambdaclient.New(clientsSession)

	logtypesAPI := &logtypesapi.LogTypesAPILambdaClient{
		LambdaName: logtypesapi.LambdaName,
		LambdaAPI:  lambdaClient,
	}

	resolver := logtypes.ChainResolvers(
		registry.NativeLogTypesResolver(),
		&logtypesapi.Resolver{
			LogTypesAPI: logtypesAPI,
		},
	)

	handler := datacatalog.LambdaHandler{
		ProcessedDataBucket: config.ProcessedDataBucket,
		QueueURL:            config.QueueURL,
		AthenaWorkgroup:     config.AthenaWorkgroup,
		ListAvailableLogTypes: func(ctx context.Context) ([]string, error) {
			reply, err := logtypesAPI.ListAvailableLogTypes(ctx)
			if err != nil {
				return nil, err
			}
			return reply.LogTypes, nil
		},
		GlueClient:   glue.New(clientsSession),
		Resolver:     resolver,
		AthenaClient: athena.New(clientsSession),
		SQSClient:    sqs.New(clientsSession),
		Logger:       logger,
	}

	lambda.StartHandler(&handler)
}
