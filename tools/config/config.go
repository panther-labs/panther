package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

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

// Filepath is the config settings file
const Filepath = "deployments/panther_config.yml"

// PantherConfig describes the panther_config.yml file.
type PantherConfig struct {
	BucketsParameterValues    BucketsParameters    `yaml:"BucketsParameterValues"`
	BackendParameterValues    BackendParameters    `yaml:"BackendParameterValues"`
	FrontendParameterValues   FrontendParameters   `yaml:"FrontendParameterValues"`
	MonitoringParameterValues MonitoringParameters `yaml:"MonitoringParameterValues"`
	OnboardParameterValues    OnboardingParameters `yaml:"OnboardingParameterValues"`
	PipLayer                  []string             `yaml:"PipLayer"`
	InitialAnalysisSets       []string             `yaml:"InitialAnalysisSets"`
}

type BucketsParameters struct {
	AccessLogsBucketName string `yaml:"AccessLogsBucketName"`
}

type BackendParameters struct {
	LogProcessorLambdaMemorySize int    `yaml:"LogProcessorLambdaMemorySize"`
	CloudWatchLogRetentionDays   int    `yaml:"CloudWatchLogRetentionDays"`
	Debug                        bool   `yaml:"Debug"`
	LayerVersionArns             string `yaml:"LayerVersionArns"`
	PythonLayerVersionArn        string `yaml:"PythonLayerVersionArn"`
	WebApplicationCertificateArn string `yaml:"WebApplicationCertificateArn"`
	CustomDomain                 string `yaml:"CustomDomain"`
	TracingMode                  string `yaml:"TracingMode"`
}

type FrontendParameters struct {
	WebApplicationFargateTaskCPU    int `yaml:"WebApplicationFargateTaskCPU"`
	WebApplicationFargateTaskMemory int `yaml:"WebApplicationFargateTaskMemory"`
}

type MonitoringParameters struct {
	AlarmSNSTopicARN string `yaml:"AlarmSNSTopicARN"` // where to send alarms (optional)
}

type OnboardingParameters struct {
	// whether or not to on board the account running Panther as a Cloud Security source
	OnboardSelf bool `yaml:"OnboardSelf"`
}

// Read settings from the config file
func Settings() (*PantherConfig, error) {
	bytes, err := ioutil.ReadFile(Filepath)
	if err != nil {
		return nil, err
	}

	var settings PantherConfig
	if err := yaml.Unmarshal(bytes, &settings); err != nil {
		return nil, err
	}

	return &settings, nil
}
