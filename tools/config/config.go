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

type PantherConfig struct {
	Infra      Infra      `yaml:"Infra"`
	Monitoring Monitoring `yaml:"Monitoring"`
	Setup      Setup      `yaml:"Setup"`
	Web        Web        `yaml:"Web"`
}

type Infra struct {
	BaseLayerVersionArns         string   `yaml:"BaseLayerVersionArns"`
	LogProcessorLambdaMemorySize int      `yaml:"LogProcessorLambdaMemorySize"`
	PipLayer                     []string `yaml:"PipLayer"`
	PythonLayerVersionArn        string   `yaml:"PythonLayerVersionArn"`
}

type Monitoring struct {
	AlarmSnsTopicArn           string `yaml:"AlarmSnsTopicArn"`
	CloudWatchLogRetentionDays int    `yaml:"CloudWatchLogRetentionDays"`
	Debug                      bool   `yaml:"Debug"`
	EnableS3AccessLogs         bool   `yaml:"EnableS3AccessLogs"`
	S3AccessLogsBucket         string `yaml:"S3AccessLogsBucket"`
	TracingMode                string `yaml:"TracingMode"`
}

type Setup struct {
	InitialAnalysisSets []string `yaml:"InitialAnalysisSets"`
	OnboardSelf         bool     `yaml:"OnboardSelf"`
	EnableCloudTrail    bool     `yaml:"EnableCloudTrail"`
	EnableGuardDuty     bool     `yaml:"EnableGuardDuty"`
}

type Web struct {
	CertificateArn    string `yaml:"CertificateArn"`
	CustomDomain      string `yaml:"CustomDomain"`
	FargateTaskCPU    int    `yaml:"FargateTaskCPU"`
	FargateTaskMemory int    `yaml:"FargateTaskMemory"`
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
