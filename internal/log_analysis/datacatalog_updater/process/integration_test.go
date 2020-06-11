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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	integrationTest bool
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		Setup()
	}
	os.Exit(m.Run())
}

func TestIntegrationSyncPartitions(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	// this assumes the self onboarding was enables (default true)
	syncEvent := &SyncEvent{
		Sync:     true,
		LogTypes: []string{"AWS.VPCFlow"},
	}
	err := Sync(syncEvent, time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = InvokeSyncGluePartitions(lambdaClient, syncEvent.LogTypes)
	require.NoError(t, err)
}
