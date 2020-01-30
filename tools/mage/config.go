package mage

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

const configFile = "deployments/panther_config.yml"

type bucketsParameters struct {
	AccessLogsBucketName string `yaml:"AccessLogsBucketName"`
}

type backendParameters struct {
	CloudWatchLogRetentionDays   int    `yaml:"CloudWatchLogRetentionDays"`
	Debug                        bool   `yaml:"Debug"`
	LayerVersionArns             string `yaml:"LayerVersionArns"`
	PythonLayerVersionArn        string `yaml:"PythonLayerVersionArn"`
	WebApplicationCertificateArn string `yaml:"WebApplicationCertificateArn"`
	TracingMode                  string `yaml:"TracingMode"`
}

type frontendParameters struct {
	WebApplicationFargateTaskCPU    int `yaml:"WebApplicationFargateTaskCPU"`
	WebApplicationFargateTaskMemory int `yaml:"WebApplicationFargateTaskMemory"`
}

// PantherConfig describes the panther_config.yml file.
type PantherConfig struct {
	BucketsParameterValues  bucketsParameters  `yaml:"BucketsParameterValues"`
	BackendParameterValues  backendParameters  `yaml:"BackendParameterValues"`
	FrontendParameterValues frontendParameters `yaml:"FrontendParameterValues"`
	PipLayer                []string           `yaml:"PipLayer"`
	InitialAnalysisSets     []string           `yaml:"InitialAnalysisSets"`
}
