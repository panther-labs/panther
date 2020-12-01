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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

func TestDataTypeFromS3Key(t *testing.T) {
	// fail parts test
	_, err := DataTypeFromS3Key("")
	require.Error(t, err)

	// fail dataType
	_, err = DataTypeFromS3Key("foo/bar")
	require.Error(t, err)

	// log
	dataType, err := DataTypeFromS3Key(logS3Prefix + "/some_table")
	require.NoError(t, err)
	assert.Equal(t, pantherdb.LogData, dataType)

	// rule matches
	dataType, err = DataTypeFromS3Key(ruleMatchS3Prefix + "/some_table")
	require.NoError(t, err)
	assert.Equal(t, pantherdb.RuleData, dataType)

	// rule errors
	dataType, err = DataTypeFromS3Key(ruleErrorsS3Prefix + "/some_table")
	require.NoError(t, err)
	assert.Equal(t, pantherdb.RuleErrors, dataType)

	// cloudsec
	dataType, err = DataTypeFromS3Key(cloudSecurityS3Prefix + "/some_table")
	require.NoError(t, err)
	assert.Equal(t, pantherdb.CloudSecurity, dataType)
}
