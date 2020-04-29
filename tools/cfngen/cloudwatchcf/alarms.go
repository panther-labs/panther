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
	"path/filepath"

	"github.com/aws/aws-sdk-go/service/cloudwatch"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/tools/cfngen"
	"github.com/panther-labs/panther/tools/cfnparse"
	"github.com/panther-labs/panther/tools/config"
)

const (
	documentationURL   = "https://docs.runpanther.io/operations/runbooks" // where all alarms are documented
	alarmPrefix        = "PantherAlarm"
	topicParameterName = "AlarmTopicArn" // CloudFormation parameter referenced in all generated alarms
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
	Name string

	// Use only one of Value, ValueSub or ValueRef
	Value string

	valueRef *RefString
	valueSub *SubString
}

func (m *MetricDimension) MarshalJSON() ([]byte, error) {
	if m.valueRef == nil && m.valueSub == nil {
		// Most common case - the struct can be marshaled like normal (json ignores nil valueRef)
		return jsoniter.Marshal(*m) // dereference to avoid infinite recursion
	}

	// marshal a new struct where "Value" is actually a struct with the nested ref
	if m.valueRef != nil && m.valueSub == nil {
		return jsoniter.Marshal(&struct {
			Name  string
			Value RefString
		}{
			Name:  m.Name,
			Value: *m.valueRef,
		})
	}

	// marshal a new struct where "Value" is actually a struct with the nested sub
	if m.valueRef == nil && m.valueSub != nil {
		return jsoniter.Marshal(&struct {
			Name  string
			Value SubString
		}{
			Name:  m.Name,
			Value: *m.valueSub,
		})
	}

	panic("valueRef and valueSub cannot both be set")
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
func GenerateAlarms(settings *config.PantherConfig, cfFiles ...string) ([]*Alarm, []byte, error) {
	var alarms []*Alarm
	includesBootstrap := false
	for _, path := range cfFiles {
		fileAlarms, err := generateAlarms(path, settings)
		if err != nil {
			return nil, nil, err
		}
		alarms = append(alarms, fileAlarms...)

		if filepath.Base(path) == "bootstrap.yml" {
			includesBootstrap = true
		}
	}

	resources := make(map[string]interface{})
	for _, alarm := range alarms {
		resources[cfngen.SanitizeResourceName(alarm.Properties.AlarmName)] = alarm
	}

	// generate CF using cfngen
	parameters := map[string]interface{}{
		topicParameterName: cfngen.Parameter{Type: "String"},
	}

	if includesBootstrap {
		// The bootstrap stack has AppSync and the ELB
		parameters[appsyncParameterName] = cfngen.Parameter{Type: "String"}
		parameters[elbParameterName] = cfngen.Parameter{Type: "String"}
	}

	cf, err := cfngen.NewTemplate("Panther Alarms", parameters, resources, nil).CloudFormation()
	if err != nil {
		return nil, nil, err
	}
	return alarms, cf, nil
}

func generateAlarms(fileName string, settings *config.PantherConfig) (alarms []*Alarm, err error) {
	obj, err := cfnparse.ParseTemplate(fileName)
	if err != nil {
		return nil, err
	}

	walkJSONMap(obj, func(resourceType string, resource map[string]interface{}) {
		alarms = append(alarms, alarmDispatchOnType(resourceType, resource, settings)...)
	})

	return alarms, nil
}

// dispatch on "Type" to create specific alarms
func alarmDispatchOnType(resourceType string, resource map[string]interface{}, settings *config.PantherConfig) (alarms []*Alarm) {
	switch resourceType { // this could be a map of key -> func if this gets long
	case "AWS::SNS::Topic":
		return generateSNSAlarms(resource)
	case "AWS::SQS::Queue":
		return generateSQSAlarms(resource)
	case "AWS::Serverless::Api":
		return generateAPIGatewayAlarms(resource)
	case "AWS::ElasticLoadBalancingV2::LoadBalancer":
		return generateApplicationELBAlarms(resource)
	case "AWS::AppSync::GraphQLApi":
		return generateAppSyncAlarms(resource)
	case "AWS::DynamoDB::Table":
		return generateDynamoDBAlarms(resource)
	case "AWS::Serverless::Function":
		return generateLambdaAlarms(resource, settings)
	case "AWS::StepFunctions::StateMachine":
		return generateSFNAlarms(resource)
	}
	return alarms
}
