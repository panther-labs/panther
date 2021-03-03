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

	"github.com/panther-labs/panther/internal/compliance/snapshotlogs"
	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/core/source_api/apifunctions"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/datacatalog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/awsretry"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/stringset"
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

	apiResolver := &logtypesapi.Resolver{
		LogTypesAPI:    logtypesAPI,
		NativeLogTypes: logtypes.MustMerge("native", registry.NativeLogTypes(), snapshotlogs.LogTypes()),
	}

	// Also include the cloud-security logs since they are not yet exported as managed schemas.
	chainResolver := logtypes.ChainResolvers(apiResolver, snapshotlogs.Resolver())

	// Log cases where a log type failed to resolve. Almost certainly something is amiss in the DDB.
	resolver := logtypes.ResolverFunc(func(ctx context.Context, name string) (logtypes.Entry, error) {
		entry, err := chainResolver.Resolve(ctx, name)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			// if a logType is not found, this indicates bad data ... log/alarm
			lambdalogger.FromContext(ctx).Error("cannot resolve logType", zap.String("logType", name))
			return nil, nil
		}
		return entry, nil
	})

	handler := datacatalog.LambdaHandler{
		ProcessedDataBucket: config.ProcessedDataBucket,
		QueueURL:            config.QueueURL,
		AthenaWorkgroup:     config.AthenaWorkgroup,
		ListAvailableLogTypes: func(ctx context.Context) ([]string, error) {
			reply, err := logtypesAPI.ListAvailableLogTypes(ctx)
			if err != nil {
				return nil, err
			}
			// append in snapshot logs which are always onboarded
			return stringset.Append(reply.LogTypes, logtypes.CollectNames(snapshotlogs.LogTypes())...), nil
		},
		GlueClient:   glue.New(clientsSession),
		Resolver:     resolver,
		AthenaClient: athena.New(clientsSession),
		SQSClient:    sqs.New(clientsSession),
		Logger:       logger,
	}

	// FIXME: This can be removed in a few releases after 1.16
	partitionColumnMigration(&handler, clientsSession)

	lambda.StartHandler(&handler)
}

// FIXME: This can be removed in a few releases after 1.16 after everyone has upgraded.
// FIXME: Release 1.16 adds a new partition column to the tables in Glue.
// FiXME: The below needs to execute BEFORE processing any S3 events to ensure
// FIXME: all tables are updated with the new partition column.
// FIXME: This will run once per container instantiation, testing shows this to be about 2 times per hour.
// partitionColumnMigration updates schemas if they have not had the new partition added, best effort
func partitionColumnMigration(handler *datacatalog.LambdaHandler, clientSession *session.Session) {
	zap.L().Info("partitionColumnMigration", zap.String("action", "started"))
	defer func() {
		zap.L().Info("partitionColumnMigration", zap.String("action", "finished"))
	}()

	// get the currently onboarded log types
	ctx := context.Background()
	logTypesInUse, err := apifunctions.ListLogTypes(ctx, lambdaclient.New(clientSession))
	if err != nil {
		zap.L().Error("partitionColumnMigration", zap.Error(err))
		return
	}

	if len(logTypesInUse) == 0 {
		return
	}

	// check ALL log types to see if table already has the new partition_time partition column
	needToSync := false
	for _, logType := range logTypesInUse {
		// just checking the log processing db, that should be enough
		if !pantherdb.IsInDatabase(logType, pantherdb.LogProcessingDatabase) {
			continue
		}
		getTableOutput, err := awsglue.GetTable(handler.GlueClient,
			pantherdb.LogProcessingDatabase, pantherdb.TableName(logType))
		if err != nil {
			zap.L().Warn("partitionColumnMigration", zap.Error(err))
			continue
		}
		if len(getTableOutput.Table.PartitionKeys) != 5 { // year, month, day, hour, partition_time
			needToSync = true // does not have all partitions
			break
		}
	}

	// this generally will only be called once, but for some reason if all tables are not updated it could be called again
	if needToSync {
		zap.L().Info("partitionColumnMigration",
			zap.String("action", "partition schema update"),
			zap.Any("logTypes", logTypesInUse))

		// sync all tables in all databases
		err = handler.HandleSyncDatabaseEvent(ctx, &datacatalog.SyncDatabaseEvent{
			TraceID:          "partitionColumnMigration",
			RequiredLogTypes: logTypesInUse,
		})
		if err != nil {
			zap.L().Error("partitionColumnMigration", zap.Error(err))
			return
		}
	}
}
