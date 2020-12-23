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

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

// This file registers the Panther specific assumptions about tables and partition formats with associated functions.

const (
	logS3Prefix           = "logs"
	ruleMatchS3Prefix     = "rules"
	ruleErrorsS3Prefix    = "rule_errors"
	cloudSecurityS3Prefix = "cloud_security"
)

// Returns the prefix of the table in S3 or error if it failed to generate it
func TablePrefix(database, tableName string) string {
	switch database {
	case pantherdb.LogProcessingDatabase:
		return logS3Prefix + "/" + tableName + "/"
	case pantherdb.RuleMatchDatabase:
		return ruleMatchS3Prefix + "/" + tableName + "/"
	case pantherdb.RuleErrorsDatabase:
		return ruleErrorsS3Prefix + "/" + tableName + "/"
	case pantherdb.CloudSecurityDatabase:
		return cloudSecurityS3Prefix + "/" + tableName + "/"
	default:
		panic("Unknown database provided " + database)
	}
}

func DataPrefix(databaseName string) string {
	switch databaseName {
	case pantherdb.LogProcessingDatabase:
		return logS3Prefix
	case pantherdb.RuleMatchDatabase:
		return ruleMatchS3Prefix
	case pantherdb.RuleErrorsDatabase:
		return ruleErrorsS3Prefix
	case pantherdb.CloudSecurityDatabase:
		return cloudSecurityS3Prefix
	default:
		if strings.Contains(databaseName, "test") {
			return logS3Prefix // assume logs, used for integration tests
		}
		panic(databaseName + " is not associated with an s3 prefix")
	}
}

func DataTypeFromS3Key(s3key string) (dataType pantherdb.DataType, err error) {
	keyParts := strings.Split(s3key, "/")
	if len(keyParts) < 2 {
		return "", errors.Errorf("DataTypeFromS3Key failed parse on: %s", s3key)
	}

	// dataType
	switch keyParts[0] {
	case logS3Prefix:
		dataType = pantherdb.LogData
	case ruleMatchS3Prefix:
		dataType = pantherdb.RuleData
	case ruleErrorsS3Prefix:
		dataType = pantherdb.RuleErrors
	case cloudSecurityS3Prefix:
		dataType = pantherdb.CloudSecurity
	default:
		return "", errors.Errorf("DataTypeFromS3Key cannot find data type from: %s", s3key)
	}

	return dataType, err
}
