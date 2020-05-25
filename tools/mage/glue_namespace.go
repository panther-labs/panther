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
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

// targets for managing Glue tables
type Glue mg.Namespace

// Sync Sync glue table partitions after schema change
func (t Glue) Sync() {
	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}
	glueClient := glue.New(awsSession)
	s3Client := s3.New(awsSession)

	enteredText := promptUser("Enter regex to select a subset of tables (or <enter> for all tables): ", regexValidator)
	matchTableName, _ := regexp.Compile(enteredText) // no error check already validated

	var startDate time.Time
	startDateText := promptUser("Enter a day as YYYY-MM-DD to start update (or <enter> to use create date on tables): ", dateValidator)
	if startDateText != "" {
		startDate, _ = time.Parse("2006-01-02", startDateText) // no error check already validated
	}

	// for each table, for each time partition, update schema
	for _, table := range registry.AvailableTables() {
		name := fmt.Sprintf("%s.%s", table.DatabaseName(), table.TableName())
		if !matchTableName.MatchString(name) {
			continue
		}
		logger.Infof("syncing %s", name)
		err := table.SyncPartitions(glueClient, s3Client, startDate)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
				logger.Infof("%s is not deployed, skipping", name)
			} else {
				logger.Fatalf("failed syncing %s: %v", name, err)
			}
		}

		// the rule match tables share the same structure as the logs
		name = fmt.Sprintf("%s.%s", awsglue.RuleMatchDatabaseName, table.TableName())
		ruleTable := awsglue.NewGlueTableMetadata(
			models.RuleData, table.LogType(), table.Description(), awsglue.GlueTableHourly, table.EventStruct())
		logger.Infof("syncing %s", name)
		err = ruleTable.SyncPartitions(glueClient, s3Client, startDate)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
				logger.Infof("%s is not deployed, skipping", name)
			} else {
				logger.Fatalf("failed syncing %s: %v", name, err)
			}
		}
	}
}
