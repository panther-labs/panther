// Package cfnstacks declares public constants and vars for Panther stacks and templates for use by tools
package cfnstacks

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	"github.com/pkg/errors"
)

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

const (
	// Bootstrap stacks and templates
	Bootstrap         = "panther-bootstrap"
	BootstrapTemplate = "deployments/bootstrap.yml"
	Gateway           = "panther-bootstrap-gateway"
	GatewayTemplate   = "deployments/bootstrap_gateway.yml"

	// Main stacks and templates
	Appsync             = "panther-appsync"
	AppsyncTemplate     = "deployments/appsync.yml"
	Cloudsec            = "panther-cloud-security"
	CloudsecTemplate    = "deployments/cloud_security.yml"
	Core                = "panther-core"
	CoreTemplate        = "deployments/core.yml"
	Dashboard           = "panther-cw-dashboards"
	DashboardTemplate   = "deployments/dashboards.yml"
	Frontend            = "panther-web"
	FrontendTemplate    = "deployments/web_server.yml"
	LogAnalysis         = "panther-log-analysis"
	LogAnalysisTemplate = "deployments/log_analysis.yml"
	Onboard             = "panther-onboard"
	OnboardTemplate     = "deployments/onboard.yml"
)

var (
	AllStacks = []string{
		Appsync,
		Bootstrap,
		Cloudsec,
		Core,
		Dashboard,
		Frontend,
		Gateway,
		LogAnalysis,
		Onboard,
	}
	NumStacks = len(AllStacks)
)

// GetBootstrapStack will return the above constant if `masterStack` is empty (deployed src), else look it up in the master stack
func GetBootstrapStack(cfnClient cloudformationiface.CloudFormationAPI, masterStack string) (string, error) {
	if masterStack == "" {
		return Bootstrap, nil // this is fixed for source deployments
	}
	// search through master stack to find the bootstrap stack
	output, err := cfnClient.DescribeStackResource(&cfn.DescribeStackResourceInput{
		StackName:         &masterStack,
		LogicalResourceId: aws.String("Bootstrap"),
	})
	if err != nil {
		return "", errors.WithMessagef(err, "cannot read %s", masterStack)
	}

	parsedArn, err := arn.Parse(aws.StringValue(output.StackResourceDetail.PhysicalResourceId))
	if err != nil {
		return "", errors.WithMessagef(err, "cannot parse %s", aws.StringValue(output.StackResourceDetail.PhysicalResourceId))
	}
	resourceParts := strings.Split(parsedArn.Resource, "/")
	if len(resourceParts) != 3 {
		return "", errors.Errorf("wrong number of resource parts for %s", parsedArn.Resource)
	}

	return resourceParts[1], nil // the second part has the stack name
}
