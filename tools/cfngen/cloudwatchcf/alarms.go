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
	"github.com/aws/aws-sdk-go/service/cloudwatch"

	"github.com/panther-labs/panther/tools/cfngen"
)

const (
	documentationURL   = "https://docs.runpanther.io/operations/runbooks" // where all alarms are documented
	alarmPrefix        = "PantherAlarm"
	topicParameterName = "AlarmTopicArn"
)

type Alarm struct {
	Resource   string `json:"-"` // use '-' tag so field is not serialized
	Type       string
	Properties AlarmProperties
}

// see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cw-alarm.html
type AlarmProperties struct {
	AlarmName          string
	AlarmDescription   string      `json:",omitempty"`
	AlarmActions       []RefString `json:",omitempty"`
	TreatMissingData   string      `json:",omitempty"`
	Namespace          string      `json:",omitempty"`
	MetricName         string
	Dimensions         []MetricDimension `json:",omitempty"`
	ComparisonOperator string
	EvaluationPeriods  int
	Period             int
	Threshold          float32
	Unit               string
	Statistic          string
}

type MetricDimension struct {
	Name  string
	Value string
}

type RefString struct {
	Ref string
}

func NewAlarm(resource, name, description string) *Alarm {
	return &Alarm{
		Resource: resource,
		Type:     "AWS::CloudWatch::Alarm",
		Properties: AlarmProperties{
			AlarmActions:      []RefString{{topicParameterName}},
			AlarmName:         name,
			AlarmDescription:  description,
			EvaluationPeriods: 1, // default to 1
		},
	}
}

// Metric configures alarm for basic metric
func (alarm *Alarm) Metric(namespace, metricName string, dimensions []MetricDimension) *Alarm {
	alarm.Properties.Namespace = namespace
	alarm.Properties.MetricName = metricName
	alarm.Properties.Dimensions = dimensions
	return alarm
}

// EvaluationPeriods configures alarm for specified evaluation periods
func (alarm *Alarm) EvaluationPeriods(evalPeriods int) *Alarm {
	alarm.Properties.EvaluationPeriods = evalPeriods
	return alarm
}

// SumCountThreshold configures alarm for sum-based threshold with Count units
func (alarm *Alarm) SumCountThreshold(threshold float32, period int) *Alarm {
	alarm.Properties.ComparisonOperator = cloudwatch.ComparisonOperatorGreaterThanThreshold
	alarm.Properties.Threshold = threshold
	alarm.Properties.Unit = cloudwatch.StandardUnitCount
	alarm.Properties.Period = period
	alarm.Properties.Statistic = cloudwatch.StatisticSum
	alarm.Properties.TreatMissingData = "notBreaching"
	return alarm
}

// SumNoUnitsThreshold configures alarm for sum-based threshold with Count units
func (alarm *Alarm) SumNoUnitsThreshold(threshold float32, period int) *Alarm {
	alarm.Properties.ComparisonOperator = cloudwatch.ComparisonOperatorGreaterThanThreshold
	alarm.Properties.Threshold = threshold
	alarm.Properties.Unit = cloudwatch.StandardUnitNone
	alarm.Properties.Period = period
	alarm.Properties.Statistic = cloudwatch.StatisticSum
	alarm.Properties.TreatMissingData = "notBreaching"
	return alarm
}

// MaxSecondsThreshold configures alarm for max-based threshold with Seconds units
func (alarm *Alarm) MaxSecondsThreshold(threshold float32, period int) *Alarm {
	alarm.Properties.ComparisonOperator = cloudwatch.ComparisonOperatorGreaterThanThreshold
	alarm.Properties.Threshold = threshold
	alarm.Properties.Unit = cloudwatch.StandardUnitSeconds
	alarm.Properties.Period = period
	alarm.Properties.Statistic = cloudwatch.StatisticMaximum
	alarm.Properties.TreatMissingData = "notBreaching"
	return alarm
}

// MaxMillisecondsThreshold configures alarm for max-based threshold with Milliseconds units
func (alarm *Alarm) MaxMillisecondsThreshold(threshold float32, period int) *Alarm {
	alarm.Properties.ComparisonOperator = cloudwatch.ComparisonOperatorGreaterThanThreshold
	alarm.Properties.Threshold = threshold
	alarm.Properties.Unit = cloudwatch.StandardUnitMilliseconds
	alarm.Properties.Period = period
	alarm.Properties.Statistic = cloudwatch.StatisticMaximum
	alarm.Properties.TreatMissingData = "notBreaching"
	return alarm
}

// MaxNoUnitsThreshold configures alarm for max-based threshold with MB units
func (alarm *Alarm) MaxNoUnitsThreshold(threshold float32, period int) *Alarm {
	alarm.Properties.ComparisonOperator = cloudwatch.ComparisonOperatorGreaterThanThreshold
	alarm.Properties.Threshold = threshold
	alarm.Properties.Unit = cloudwatch.StandardUnitNone
	alarm.Properties.Period = period
	alarm.Properties.Statistic = cloudwatch.StatisticMaximum
	alarm.Properties.TreatMissingData = "notBreaching"
	return alarm
}

func AlarmName(alarmType, resourceName string) string {
	return alarmPrefix + "-" + alarmType + "-" + resourceName
}

// GenerateAlarms will read the CF in yml files in the cfDir, and generate CF for CloudWatch alarms for the infrastructure.
// NOTE: this will not work for resources referenced with Refs, this code requires constant values.
func GenerateAlarms(cfDirs ...string) (alarms []*Alarm, cf []byte, err error) {
	for _, cfDir := range cfDirs {
		err := walkYamlFiles(cfDir, func(path string) (err error) {
			fileAlarms, err := generateAlarms(path)
			if err == nil {
				alarms = append(alarms, fileAlarms...)
			}
			return err
		})
		if err != nil {
			return nil, nil, err
		}
	}

	resources := make(map[string]interface{})
	for _, alarm := range alarms {
		resources[cfngen.SanitizeResourceName(alarm.Properties.AlarmName)] = alarm
	}

	// generate CF using cfngen
	parameters := map[string]interface{}{
		topicParameterName: cfngen.Parameter{
			Type: "String",
		},
	}
	cf, err = cfngen.NewTemplate("Panther Alarms", parameters, resources, nil).CloudFormation()
	if err != nil {
		return nil, nil, err
	}
	return alarms, cf, nil
}

func generateAlarms(fileName string) (alarms []*Alarm, err error) {
	yamlObj, err := readYaml(fileName)
	if err != nil {
		return nil, err
	}

	walkYamlMap(yamlObj, func(resourceType string, resource map[interface{}]interface{}) {
		alarms = append(alarms, alarmDispatchOnType(resourceType, resource)...)
	})

	return alarms, nil
}

// dispatch on "Type" to create specific alarms
func alarmDispatchOnType(resourceType string, resource map[interface{}]interface{}) (alarms []*Alarm) {
	switch resourceType { // this could be a map of key -> func if this gets long
	case "AWS::SNS::Topic":
		return generateSNSAlarms(resource)
	case "AWS::SQS::Queue":
		return generateSQSAlarms(resource)
		//case "AWS::Serverless::Api":
		//	return generateAPIGatewayAlarms(resource)
		//case "AWS::ElasticLoadBalancingV2::LoadBalancer":
		//	return generateApplicationELBAlarms(resource)
		//case "AWS::AppSync::GraphQLApi":
		//	return generateAppSyncAlarms(resource)
		//case "AWS::DynamoDB::Table":
		//	return generateDynamoDBAlarms(resource)
		//case "AWS::Serverless::Function":
		//	return generateLambdaAlarms(resource)
	}
	return alarms
}
