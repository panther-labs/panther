package config

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
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

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
	TracingMode                string `yaml:"TracingMode"`
}

type Setup struct {
	OnboardSelf         bool             `yaml:"OnboardSelf"`
	EnableS3AccessLogs  bool             `yaml:"EnableS3AccessLogs"`
	EnableCloudTrail    bool             `yaml:"EnableCloudTrail"`
	EnableGuardDuty     bool             `yaml:"EnableGuardDuty"`
	S3AccessLogsBucket  string           `yaml:"S3AccessLogsBucket"`
	InitialAnalysisSets []string         `yaml:"InitialAnalysisSets"`
	LogRetention        LogRetention     `yaml:"LogRetention"`
	LogSubscriptions    LogSubscriptions `yaml:"LogSubscriptions"`
	Athena              Athena           `yaml:"Athena"`
}

type LogRetention struct {
	ProcessedDataBucketRetentionDays  int `yaml:"ProcessedDataBucketRetentionDays"`
	HistoricalDataBucketRetentionDays int `yaml:"HistoricalDataBucketRetentionDays"`
}

type LogSubscriptions struct {
	PrincipalARNs []string `yaml:"PrincipalARNs"`
}

type Athena struct {
	PantherTablesOnly bool     `yaml:"PantherTablesOnly"`
	S3ARNs            []string `yaml:"S3ARNs"`
}

type Web struct {
	CertificateArn string `yaml:"CertificateArn"`
	CustomDomain   string `yaml:"CustomDomain"`
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
