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
	"github.com/panther-labs/panther/tools/mage/build"
)

/*
Dashboards are generated rather than explicitly defined
as json/yml text files because a dashboard is define as a JSON
string property in a resource. If we were to declare this in text file, the developer
would have to properly JSON escape the string AND do a Fn::Sub to
insert the region in the JSON at various places. This is tedious
and error prone. Generating the CF files is much simpler for the
developer and easier to read.

The methodology for adding dashboards is to:
1. Design in the AWS CloutWatch Console
2. Use the "View/edit source" option to copy the JSON for the dashboard
3. Create a new file holding a global var bound to the JSON
4. Add a line to Dashboards() below instantiating the CF dashboard resource
*/

// Dashboards returns all the declared dashboards
func Dashboards() (dashboards []*build.Dashboard) {
	dashboards = append(dashboards, build.NewDashboard("PantherOverview", overviewJSON))
	dashboards = append(dashboards, build.NewDashboard("PantherCloudSecurity", infraJSON))
	dashboards = append(dashboards, build.NewDashboard("PantherAlertProcessing", alertsJSON))
	dashboards = append(dashboards, build.NewDashboard("PantherRemediation", remediationJSON))
	dashboards = append(dashboards, build.NewDashboard("PantherLogAnalysis", logProcessingJSON))
	return dashboards
}
