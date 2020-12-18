package awslogs

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

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

func TestAppendAnyAWSAccountIds(t *testing.T) {
	event := AWSPantherLog{}
	value := "012345678912"
	expectedAny := parsers.PantherAnyString{value}
	event.AppendAnyAWSAccountIds(value)
	require.Equal(t, expectedAny, event.PantherAnyAWSAccountIds)

	event = AWSPantherLog{}
	event.AppendAnyAWSAccountIdPtrs(&value)
	require.Equal(t, expectedAny, event.PantherAnyAWSAccountIds)

	// these should fail validation
	event = AWSPantherLog{}
	value = "012345" // too short
	expectedAny = nil
	event.AppendAnyAWSAccountIds(value)
	require.Equal(t, expectedAny, event.PantherAnyAWSAccountIds)

	event = AWSPantherLog{}
	value = "abc345678912" // not all numbers
	expectedAny = nil
	event.AppendAnyAWSAccountIds(value)
	require.Equal(t, expectedAny, event.PantherAnyAWSAccountIds)
}

func TestAppendAnyAWSInstanceIds(t *testing.T) {
	event := AWSPantherLog{}
	value := "a"
	expectedAny := parsers.PantherAnyString{value}
	event.AppendAnyAWSInstanceIds(value)
	require.Equal(t, expectedAny, event.PantherAnyAWSInstanceIds)

	event = AWSPantherLog{}
	event.AppendAnyAWSInstanceIdPtrs(&value)
	require.Equal(t, expectedAny, event.PantherAnyAWSInstanceIds)
}

func TestAppendAnyAWSARNs(t *testing.T) {
	event := AWSPantherLog{}
	value := "a"
	expectedAny := parsers.PantherAnyString{value}
	event.AppendAnyAWSARNs(value)
	require.Equal(t, expectedAny, event.PantherAnyAWSARNs)

	event = AWSPantherLog{}
	event.AppendAnyAWSARNPtrs(&value)
	require.Equal(t, expectedAny, event.PantherAnyAWSARNs)
}

func TestAppendAnyAWSTags(t *testing.T) {
	event := AWSPantherLog{}
	value := "a"
	expectedAny := parsers.PantherAnyString{value}
	event.AppendAnyAWSTags(value)
	require.Equal(t, expectedAny, event.PantherAnyAWSTags)

	event = AWSPantherLog{}
	event.AppendAnyAWSTagPtrs(&value)
	require.Equal(t, expectedAny, event.PantherAnyAWSTags)
}
