package mage

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
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/cfnstacks"
)

// targets for managing Glue tables
type Glue mg.Namespace

// Sync Sync glue table partitions after schema change
func (t Glue) Sync() {
	getSession()
	glueClient := glue.New(awsSession)
	s3Client := s3.New(awsSession)

	enteredText := prompt.Read("Enter regex to select a subset of tables (or <enter> for all tables): ",
		prompt.RegexValidator)
	matchTableName, _ := regexp.Compile(enteredText) // no error check already validated

	var startDate time.Time
	startDateText := prompt.Read("Enter a day as YYYY-MM-DD to start update (or <enter> to use create date on tables): ",
		prompt.DateValidator)
	if startDateText != "" {
		startDate, _ = time.Parse("2006-01-02", startDateText) // no error check already validated
	}

	// for each registered table, update the table, for each time partition, update the schema
	for _, table := range updateRegisteredTables(glueClient) {
		name := fmt.Sprintf("%s.%s", table.DatabaseName(), table.TableName())
		if !matchTableName.MatchString(name) {
			continue
		}
		logger.Infof("syncing partitions for %s", name)
		_, err := table.SyncPartitions(glueClient, s3Client, startDate, nil)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
				logger.Infof("%s is not deployed, skipping", name)
			} else {
				logger.Fatalf("failed syncing %s: %v", name, err)
			}
		}
	}
}

func updateRegisteredTables(glueClient *glue.Glue) (tables []*awsglue.GlueTableMetadata) {
	const processDataBucketStack = cfnstacks.Bootstrap
	client := cloudformation.New(awsSession)
	outputs := awscfn.StackOutputs(client, logger, processDataBucketStack)
	var dataBucket string
	if dataBucket = outputs["ProcessedDataBucket"]; dataBucket == "" {
		logger.Fatalf("could not find processed data bucket in %s outputs", processDataBucketStack)
	}

	var listOutput []*models.SourceIntegration
	var listInput = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{},
	}
	if err := genericapi.Invoke(lambda.New(awsSession), "panther-source-api", listInput, &listOutput); err != nil {
		logger.Fatalf("error calling source-api to list integrations: %v", err)
	}

	// get unique set of logTypes
	logTypeSet := make(map[string]struct{})
	for _, integration := range listOutput {
		if integration.IntegrationType == models.IntegrationTypeAWS3 {
			for _, logType := range integration.LogTypes {
				logTypeSet[logType] = struct{}{}
			}
		}
	}

	for logType := range logTypeSet {
		logger.Infof("updating registered tables for %s", logType)
		logTable, ruleTable, err := gluetables.CreateOrUpdateGlueTablesForLogType(glueClient, logType, dataBucket)
		if err != nil {
			logger.Fatalf("error updating table definitions: %v", err)
		}
		tables = append(tables, logTable)
		tables = append(tables, ruleTable)
	}

	// update the views with the new tables
	if err := athenaviews.CreateOrReplaceViews(glueClient, athena.New(awsSession)); err != nil {
		logger.Fatalf("error updating table views: %v", err)
	}

	return tables
}
