package api

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
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestAPI_UpdateStatus_FailsIfIntegrationNotExists(t *testing.T) {
	testutils.IntegrationTest(t) // test runs the API handler locally but hits a real DynamoDB

	awsSession := session.Must(session.NewSession())
	testAPI := &API{
		AwsSession: awsSession,
		DdbClient:  ddb.New(awsSession, "panther-source-integrations"),
	}

	input := models.UpdateStatusInput{
		IntegrationID:     "abcdefgh-abcd-abcd-abcd-abcdefghijkl",
		LastEventReceived: time.Now(),
	}
	err := testAPI.UpdateStatus(&input)

	require.Error(t, err)
}
