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
	"github.com/panther-labs/panther/tools/cfngen"
	"github.com/panther-labs/panther/tools/cfnparse"
)

// https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html
const (
	metricFilterNamespace = "Panther"

	lambdaErrorsMetricFilterName = "errors"
	lambdaWarnsMetricFilterName  = "warns"
	lambdaMemoryMetricFilterName = "memory"
)

type MetricFilter struct {
	Type       string
	Properties MetricFilterProperties
}

type MetricFilterProperties struct {
	FilterPattern         string
	LogGroupName          string
	MetricTransformations []MetricTransformations
}

type MetricTransformations struct {
	DefaultValue    int
	MetricNamespace string
	MetricName      string
	MetricValue     string
}

func NewGoLambdaErrorMetricFilter(lambdaName string) *MetricFilter {
	return NewLambdaMetricFilter(lambdaName, lambdaErrorsMetricFilterName, `{ $.level = "error" }`, "1")
}

func NewPythonLambdaErrorMetricFilter(lambdaName string) *MetricFilter {
	return NewLambdaMetricFilter(lambdaName, lambdaErrorsMetricFilterName, `[ level="[ERROR]" ]`, "1")
}

func NewGoLambdaWarnMetricFilter(lambdaName string) *MetricFilter {
	return NewLambdaMetricFilter(lambdaName, lambdaWarnsMetricFilterName, `{ $.level = "warn" }`, "1")
}

func NewPythonLambdaWarnMetricFilter(lambdaName string) *MetricFilter {
	return NewLambdaMetricFilter(lambdaName, lambdaWarnsMetricFilterName, `[ level="[WARN]" ]`, "1")
}

func NewLambdaMemoryMetricFilter(lambdaName string) *MetricFilter {
	return NewLambdaMetricFilter(lambdaName, lambdaMemoryMetricFilterName,
		`[ report_label="REPORT", ..., label="Used:", max_memory_used_value, unit="MB" ]`, `$max_memory_used_value`)
}

func NewLambdaMetricFilter(lambdaName, metricName, filterPattern, metricValue string) *MetricFilter {
	return &MetricFilter{
		Type: "AWS::Logs::MetricFilter",
		Properties: MetricFilterProperties{
			FilterPattern: filterPattern,
			LogGroupName:  "/aws/lambda/" + lambdaName,
			MetricTransformations: []MetricTransformations{
				{
					DefaultValue:    0,
					MetricNamespace: metricFilterNamespace,
					MetricName:      LambdaMetricFilterName(lambdaName, metricName),
					MetricValue:     metricValue,
				},
			},
		},
	}
}

func LambdaMetricFilterName(lambdaName, metricName string) string {
	return lambdaName + "-" + metricName
}

// GenerateMetrics will read the CF in yml files in the cfDirs, and generate CF for CloudWatch metric filters for the infrastructure.
// NOTE: this will not work for resources referenced with Refs, this code requires constant values.
func GenerateMetrics(cfFiles ...string) ([]byte, error) {
	var metricFilters []*MetricFilter

	for _, path := range cfFiles {
		fileMetricFilters, err := generateMetricFilters(path)
		if err != nil {
			return nil, err
		}
		metricFilters = append(metricFilters, fileMetricFilters...)
	}

	resources := make(map[string]interface{})
	for _, metricFilter := range metricFilters {
		resources[cfngen.SanitizeResourceName(metricFilter.Properties.MetricTransformations[0].MetricName)] = metricFilter
	}

	// generate CF using cfngen
	return cfngen.NewTemplate("Panther Metrics", nil, resources, nil).CloudFormation()
}

func generateMetricFilters(fileName string) (metricFilters []*MetricFilter, err error) {
	jsonObj, err := cfnparse.ParseTemplate(fileName)
	if err != nil {
		return nil, err
	}

	walkJSONMap(jsonObj, func(resourceType string, resource map[string]interface{}) {
		metricFilters = append(metricFilters, metricFilterDispatchOnType(resourceType, resource)...)
	})

	return metricFilters, nil
}

// dispatch on "Type" to create specific metric filters
func metricFilterDispatchOnType(resourceType string, resource map[string]interface{}) (metricFilters []*MetricFilter) {
	switch resourceType { // could be a map of key -> func if this gets long
	case "AWS::Serverless::Function":
		return generateLambdaMetricFilters(resource)
	}
	return metricFilters
}
