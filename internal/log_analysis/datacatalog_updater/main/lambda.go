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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/process"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

/*
   The datacatalog_updater lambda takes 2 kinds of events:
     1) SQS messages with s3 paths of files written, these cause Glue partitions to be registered.
     2) Events that request compacted partitions be registered

   Operation:
     1) S3 path from an SQS event is tested to see if a new Glue hourly partition needs to be created
	     - if NO, then return
     2) Glue partition is created
     3) An async request is made to Athena API to convert the new partition to Parquet 2 HOURS FROM NOW
         - The Athena API implements this using a Step Function that waits 2 hours then executes
           CREATE TABLE AS SELECT ... (aka CTAS) to convert the partition to Parquet under a new S3 prefix.
         - The Athena API Step Function allows 'userData' to be passed through the function to the lambda callback.
           In this case the 'userData' is a JSON snippet to track:
                     1) the table and partition being converted
                     2) the number of failed executions
         - The S3 prefixes where the new data is written all are unique (they have an appended uuid) so that
           the process can be re-run on failures without interference. Only successful prefixes will be registered.
           Currently we have no "cleanup" implemented for failed compactions for 2 reasons:
                    1) this should be infrequent and not expensive, hence the code complexity for clean up is worth it.
                    2) the data is useful for troubleshooting
     4) When done (success or fail) the Step Function executes a lambda callback to _this_ lambda
        passing the userData with the above information. The Glue partition is updated, setting type to Parquet
        and Location to the new S3 prefix.
          - If the step function failed, we log an error and execute again up to 'maxCompactionRetries'
            without a configured initial delay.

    This lambda and the Step Function have automatically generated CW alarms on failures.
*/

type DataCatalogEvent struct {
	events.SQSEvent
	process.LambdaInput
}

func handle(ctx context.Context, event DataCatalogEvent) (err error) {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err,
			zap.Int("sqsMessageCount", len(event.Records)))
	}()

	if event.UpdateParquetPartition != nil { // updates partition after parquet generation
		_, err = process.UpdateParquetPartition(event.UpdateParquetPartition)
	} else { // process notification to create partitions as needed
		err = process.SQS(event.SQSEvent)
	}

	return err
}

func main() {
	process.SessionInit()
	lambda.Start(handle)
}
