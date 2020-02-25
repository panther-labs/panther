package cloudwatchcf

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"bytes"
	"fmt"
	"regexp"

	"github.com/panther-labs/panther/tools/cfngen"
)

const (
	replaceRegionTemplate = `"region": "%s"`
)

var (
	replaceRegion = regexp.MustCompile(`"region":\s*"(?:[\w\-]*)"`)
)

type DashboardProperties struct {
	DashboardBody string
	DashboardName string
}

type Dashboard struct {
	Type       string
	Properties DashboardProperties
}

func NewDashboard(awsRegion, name, body string) (db *Dashboard) {
	/*
	 Most graphs in CW dashboards require a region to be specified. In order to
	 allow a developer to simply paste the JSON from the CloudWatch dashboard,
	 we will regexp replace the specified region with the parameter passed into this function.
	 This is much cleaner and easier than using CF Fn::Sub with escaped JSON.
	*/
	body = replaceRegion.ReplaceAllString(body, fmt.Sprintf(replaceRegionTemplate, awsRegion))
	db = &Dashboard{
		Type: "AWS::CloudWatch::Dashboard",
		Properties: DashboardProperties{
			DashboardBody: body,
			DashboardName: name + "-" + awsRegion,
		},
	}
	return
}

func GenerateDashboards(dashboards []*Dashboard) (cf []byte, err error) {
	resources := make(map[string]interface{})
	for _, dashboard := range dashboards {
		resources[cfngen.SanitizeResourceName(dashboard.Properties.DashboardName)] = dashboard
	}
	// generate CF using cfngen
	cfTemplate := cfngen.NewTemplate("Panther Dashboards", nil, resources, nil)
	buffer := bytes.Buffer{}
	err = cfTemplate.WriteCloudFormation(&buffer)
	buffer.WriteString("\n") // add trailing \n that is expected in text files
	return buffer.Bytes(), err
}
