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
	"regexp"
)

type Dashboard struct {
	Type       string              `yaml:"Type"`
	Properties DashboardProperties `yaml:"Properties"`
}

type DashboardProperties struct {
	DashboardBody SubString `yaml:"DashboardBody"`
	DashboardName SubString `yaml:"DashboardName"`
}

type SubString struct {
	Sub string `yaml:"Fn::Sub"`
}

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

var replaceRegion = regexp.MustCompile(`"region":\s*"(?:[\w\-]*)"`)

// Dashboards returns all the declared dashboards
func Dashboards() (dashboards []*Dashboard) {
	return []*Dashboard{NewDashboard("PantherLogAnalysis", logProcessingJSON)}
}

func NewDashboard(name, body string) *Dashboard {
	/*
	 Most graphs in CW dashboards require a region to be specified. In order to
	 allow a developer to simply paste the JSON from the CloudWatch dashboard,
	 we will regexp replace the region in the raw json with the AWS::Region parameter.
	 This is much cleaner and easier than using CF Fn::Sub with escaped JSON.
	*/

	return &Dashboard{
		Type: "AWS::CloudWatch::Dashboard",
		Properties: DashboardProperties{
			DashboardBody: SubString{replaceRegion.ReplaceAllString(body, `"region": "${AWS::Region}"`)},
			DashboardName: SubString{name + "-${AWS::Region}"},
		},
	}
}
