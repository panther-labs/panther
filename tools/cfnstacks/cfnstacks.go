// Package cfnstacks declares public constants and vars for Panther stacks and templates for use by tools
package cfnstacks

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
	// API stacks and templates
	APITemplate         = "deployments/bootstrap_gateway.yml"
	APIEmbeddedTemplate = "out/deployments/embedded.bootstrap_gateway.yml"

	// Bootstrap stacks and templates
	Bootstrap         = "panther-bootstrap"
	BootstrapTemplate = "deployments/bootstrap.yml"
	Gateway           = "panther-bootstrap-gateway"
	GatewayTemplate   = APIEmbeddedTemplate

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
