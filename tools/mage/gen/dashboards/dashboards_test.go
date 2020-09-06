package dashboards

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
)

func TestDashboards(t *testing.T) {
	name := "TestDashboard"
	dashboardJSON := `
{
"some-dashboard_parameter": "foo",
"region": "replace-me",
}
`
	// the region in the JSON should get replaced and the name the region appended
	expectedDashboardJSON := `
{
"some-dashboard_parameter": "foo",
"region": "${AWS::Region}",
}
`
	expectedDashboard := &Dashboard{
		Type: "AWS::CloudWatch::Dashboard",
		Properties: DashboardProperties{
			DashboardName: SubString{name + "-${AWS::Region}"},
			DashboardBody: SubString{expectedDashboardJSON},
		},
	}

	dashboard := NewDashboard(name, dashboardJSON)
	require.Equal(t, expectedDashboard, dashboard)
}
