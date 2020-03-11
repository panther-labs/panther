package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/awsglue"
)

// targets for managing Glue tables
type Glue mg.Namespace

// Sync Sync glue table partitions after schema change
func (t Glue) Sync() {
	var enteredText string

	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}
	glueClient := glue.New(awsSession)

	enteredText = promptUser("Enter regex to select a subset of tables (or <enter> for all tables): ", regexValidator)
	matchTableName, _ := regexp.Compile(enteredText) // no error check already validated

	syncPartitions(glueClient, matchTableName)
}

func syncPartitions(glueClient *glue.Glue, matchTableName *regexp.Regexp) {
	// for each table, for each time partition, update schema
	for _, table := range registry.AvailableTables() {
		name := fmt.Sprintf("%s.%s", table.DatabaseName(), table.TableName())
		if !matchTableName.MatchString(name) {
			continue
		}
		logger.Infof("syncing %s", name)
		err := table.SyncPartitions(glueClient)
		if err != nil {
			logger.Fatalf("failed syncing %s: %v", name, err)
		}
		// the rule match tables share the same structure as the logs
		name = fmt.Sprintf("%s.%s", awsglue.RuleMatchDatabaseName, table.TableName())
		ruleTable := awsglue.NewGlueTableMetadata(
			models.RuleData, table.LogType(), table.Description(), awsglue.GlueTableHourly, table.EventStruct())
		logger.Infof("syncing %s", name)
		err = ruleTable.SyncPartitions(glueClient)
		if err != nil {
			logger.Fatalf("failed syncing %s: %v", name, err)
		}
	}
}

func regexValidator(text string) error {
	if _, err := regexp.Compile(text); err != nil {
		return fmt.Errorf("invalid regex: %v", err)
	}
	return nil
}
