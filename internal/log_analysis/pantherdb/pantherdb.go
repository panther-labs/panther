package pantherdb

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

	"github.com/panther-labs/panther/internal/compliance/snapshotlogs"
)

const (
	CloudSecurityDatabase            = "panther_cloudsecurity"
	CloudSecurityDatabaseDescription = "Hold tables related to Panther cloud security scanning"

	LogProcessingDatabase            = "panther_logs"
	LogProcessingDatabaseDescription = "Holds tables with data from Panther log processing"

	RuleMatchDatabase            = "panther_rule_matches"
	RuleMatchDatabaseDescription = "Holds tables with data from Panther rule matching (same table structure as panther_logs)"

	ViewsDatabase            = "panther_views"
	ViewsDatabaseDescription = "Holds views useful for querying Panther data"

	RuleErrorsDatabase            = "panther_rule_errors"
	RuleErrorsDatabaseDescription = "Holds tables with data that failed Panther rule matching (same table structure as panther_logs)"

	TempDatabase            = "panther_temp"
	TempDatabaseDescription = "Holds temporary tables used for processing tasks"
)

var Databases = map[string]string{
	CloudSecurityDatabase: CloudSecurityDatabaseDescription,
	LogProcessingDatabase: LogProcessingDatabaseDescription,
	RuleMatchDatabase:     RuleMatchDatabaseDescription,
	RuleErrorsDatabase:    RuleErrorsDatabaseDescription,
	ViewsDatabase:         ViewsDatabaseDescription,
	TempDatabase:          TempDatabaseDescription,
}

// The type of data that are stored in the Panther
type DataType string

const (
	// LogData represents log data processed by Panther
	LogData DataType = "LogData"
	// RuleData represents parsed log data that have matched some rule
	RuleData DataType = "RuleMatches"
	// RuleData represents parsed log data that have generated an error while running over rules
	RuleErrors DataType = "RuleErrors"
	// CloudSecurity represents CloudSecurity data processed by Panther
	CloudSecurity DataType = "CloudSecurity"
)

// Returns the datatype associated to this LogType
func GetDataType(logtype string) DataType {
	if snapshotlogs.LogTypes().Find(logtype) != nil {
		return CloudSecurity
	}
	return LogData
}

// Returns true if the given logtype has a corresponding table in a Database
func IsInDatabase(logtype, db string) bool {
	dt := GetDataType(logtype)
	switch dt {
	case CloudSecurity:
		// CloudSecurity data can be found only in CloudSecurity Database or in the temporary database
		return db == CloudSecurityDatabase || db == TempDatabase
	default:
		// non-cloud security data can be found in any database - apart from CloudSecurity database
		return db != CloudSecurityDatabase
	}
}

// Returns the name of the table for the given log type
func TableName(logType string) string {
	// clean table name to make sql friendly
	tableName := strings.Replace(logType, ".", "_", -1) // no '.'
	return strings.ToLower(tableName)
}

// Returns the database in which exists the
func DatabaseName(typ DataType) string {
	switch typ {
	case LogData:
		return LogProcessingDatabase
	case RuleData:
		return RuleMatchDatabase
	case RuleErrors:
		return RuleErrorsDatabase
	case CloudSecurity:
		return CloudSecurityDatabase
	default:
		panic("Unknow DataType " + typ)
	}
}
