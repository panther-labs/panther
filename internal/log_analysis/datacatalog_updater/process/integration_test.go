package process

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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

const (
	// this needs to match the CF where we create the WG in bootstrap_gateway.yml
	workgroup = "Panther"
)

var (
	integrationTest bool
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		os.Setenv("ATHENA_WORKGROUP", workgroup)
		Setup()
	}
	os.Exit(m.Run())
}

func TestIntegrationSyncPartitions(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}
	// this assumes the self onboarding was enables (default true)
	err := InvokeBackgroundSync(context.Background(), lambdaClient, &SyncEvent{
		LogTypes: []string{"AWS.VPCFlow"},
		DatabaseNames: []string{
			awsglue.LogProcessingDatabaseName,
			awsglue.RuleErrorsDatabaseName,
			awsglue.RuleMatchDatabaseName,
		},
	})
	require.NoError(t, err)
}
