package deploy

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
	"gopkg.in/yaml.v3"

	"github.com/panther-labs/panther/tools/mage/util"
)

const ConfigFilepath = "deployments/panther_config.yml"

type PantherConfig struct {
	Infra      Infra      `yaml:"Infra"`
	Monitoring Monitoring `yaml:"Monitoring"`
	Setup      Setup      `yaml:"Setup"`
	Web        Web        `yaml:"Web"`
}

type Infra struct {
	BaseLayerVersionArns               string   `yaml:"BaseLayerVersionArns"`
	LoadBalancerSecurityGroupCidr      string   `yaml:"LoadBalancerSecurityGroupCidr"`
	LogProcessorLambdaMemorySize       int      `yaml:"LogProcessorLambdaMemorySize"`
	LogProcessorLambdaSQSReadBatchSize string   `yaml:"LogProcessorLambdaSQSReadBatchSize"`
	PipLayer                           []string `yaml:"PipLayer"`
	KvTableBillingMode                 string   `yaml:"KvTableBillingMode"`
	PythonLayerVersionArn              string   `yaml:"PythonLayerVersionArn"`
	PythonManagedPolicyArn             string   `yaml:"PythonManagedPolicyArn"`
	PythonAssumableRoleArns            []string `yaml:"PythonAssumableRoleArns"`
	SecurityGroupID                    string   `yaml:"SecurityGroupID"`
	SubnetOneID                        string   `yaml:"SubnetOneID"`
	SubnetTwoID                        string   `yaml:"SubnetTwoID"`
	SubnetOneIPRange                   string   `yaml:"SubnetOneIPRange"`
	SubnetTwoIPRange                   string   `yaml:"SubnetTwoIPRange"`
	VpcID                              string   `yaml:"VpcID"`
}

type Monitoring struct {
	AlarmSnsTopicArn           string `yaml:"AlarmSnsTopicArn"`
	CloudWatchLogRetentionDays int    `yaml:"CloudWatchLogRetentionDays"`
	Debug                      bool   `yaml:"Debug"`
	TracingMode                string `yaml:"TracingMode"`
}

type Setup struct {
	Company               Company          `yaml:"Company"`
	FirstUser             FirstUser        `yaml:"FirstUser"`
	OnboardSelf           bool             `yaml:"OnboardSelf"`
	EnableS3AccessLogs    bool             `yaml:"EnableS3AccessLogs"`
	EnableCloudTrail      bool             `yaml:"EnableCloudTrail"`
	EnableGuardDuty       bool             `yaml:"EnableGuardDuty"`
	S3AccessLogsBucket    string           `yaml:"S3AccessLogsBucket"`
	DataReplicationBucket string           `yaml:"DataReplicationBucket"`
	InitialAnalysisSets   []string         `yaml:"InitialAnalysisSets"`
	LogSubscriptions      LogSubscriptions `yaml:"LogSubscriptions"`
}

type Company struct {
	DisplayName string `yaml:"DisplayName"`
	Email       string `yaml:"Email"`
}

type LogSubscriptions struct {
	PrincipalARNs []string `yaml:"PrincipalARNs"`
}

type Web struct {
	CertificateArn string `yaml:"CertificateArn"`
	CustomDomain   string `yaml:"CustomDomain"`
}

type FirstUser struct {
	GivenName  string `yaml:"GivenName"`
	FamilyName string `yaml:"FamilyName"`
	Email      string `yaml:"Email"`
}

// Read settings from the config file
func Settings() (*PantherConfig, error) {
	bytes := util.MustReadFile(ConfigFilepath)

	var settings PantherConfig
	if err := yaml.Unmarshal(bytes, &settings); err != nil {
		return nil, err
	}

	return &settings, nil
}
