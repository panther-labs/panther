package cloudwatchcf

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

var (
	replaceRegion = regexp.MustCompile(`"region":\s*"(?:[\w\-]*)"`)
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
