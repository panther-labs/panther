package awsglue

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
	"strings"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
)

// This file registers the Panther specific assumptions about tables and partition formats with associated functions.

const (
	logS3Prefix       = "logs"
	ruleMatchS3Prefix = "rules"

	LogProcessingDatabaseName        = "panther_logs"
	LogProcessingDatabaseDescription = "Holds tables with data from Panther log processing"

	RuleMatchDatabaseName        = "panther_rule_matches"
	RuleMatchDatabaseDescription = "Holds tables with data from Panther rule matching (same table structure as panther_logs)"

	ViewsDatabaseName        = "panther_views"
	ViewsDatabaseDescription = "Holds views useful for querying Panther data"

	TempDatabaseName        = "panther_temp"
	TempDatabaseDescription = "Holds temporary tables used for processing tasks"
)

var (
	// PantherDatabases is exposed as public var to allow code to get/lookup the Panther databases
	PantherDatabases = map[string]string{
		LogProcessingDatabaseName: LogProcessingDatabaseDescription,
		RuleMatchDatabaseName:     RuleMatchDatabaseDescription,
		ViewsDatabaseName:         ViewsDatabaseDescription,
	}
)

// Returns the prefix of the table in S3 or error if it failed to generate it
func getDatabase(dataType models.DataType) string {
	if dataType == models.LogData {
		return LogProcessingDatabaseName
	}
	return RuleMatchDatabaseName
}

// Returns the prefix of the table in S3 or error if it failed to generate it
func getTablePrefix(dataType models.DataType, tableName string) string {
	if dataType == models.LogData {
		return logS3Prefix + "/" + tableName + "/"
	}
	return ruleMatchS3Prefix + "/" + tableName + "/"
}

func GetTableName(logType string) string {
	// clean table name to make sql friendly
	tableName := strings.Replace(logType, ".", "_", -1) // no '.'
	return strings.ToLower(tableName)
}

func GetDataPrefix(databaseName string) string {
	switch databaseName {
	case LogProcessingDatabaseName:
		return logS3Prefix
	case RuleMatchDatabaseName:
		return ruleMatchS3Prefix
	default:
		if strings.Contains(databaseName, "test") {
			return logS3Prefix // assume logs, used for integration tests
		}
		panic(databaseName + " is not associated with an s3 prefix")
	}
}
