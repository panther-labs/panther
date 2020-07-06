package metrics

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
	"errors"
	"time"

	"go.uber.org/zap"
)

// Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
//
// The AWS embedded metric format allows us to log to CloudWatch directly, while AWS automatically
// generates appropriate metric filters based on the dimension fields that we log.

// An EmbeddedMetric is the value mapped to the required top level member of the root node `_aws` in
// the AWS embedded metric format.
type EmbeddedMetric struct {
	// A slice of MetricDirectiveObjects used to instruct CloudWatch to extract metrics from the
	// root node of the LogEvent.
	CloudWatchMetrics []MetricDirectiveObject
	// A number representing the time stamp used for metrics extracted from the event. Values MUST
	// be expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
	Timestamp int64
}

// A MetricDirectiveObject instructs downstream services that the LogEvent contains metrics that
// will be extracted and published to CloudWatch.
type MetricDirectiveObject struct {
	// A string representing the CloudWatch namespace for the metric.
	Namespace  string
	Dimensions []DimensionSet
	// An slice of Metrics. This slice  MUST NOT contain more than 100 Metrics.
	Metrics []Metric
}

const maxMetricsPerDirective = 100

// A DimensionSet is a slice of strings containing the dimension keys that will be applied to all
// metrics logged. The values within this slice MUST also be members on the root node, referred to
// as the Target Members
//
// A DimensionSet MUST NOT contain more than 9 dimension keys.
//
// The target member defines a dimension that will be published as part of the metric identity.
// Every DimensionSet used creates a new metric in CloudWatch.
type DimensionSet = []string

const maxDimensionsKeys = 9

// Metric unit contains a name and a unit used to describe a particular metric value
type Metric struct {
	// A reference to a metric Target Member. Each Metric Name must also be a top level member.
	Name string
	// Valid Unit values (defaults to None):
	// Seconds | Microseconds | Milliseconds | Bytes | Kilobytes | Megabytes | Gigabytes | Terabytes
	// Bits | Kilobits | Megabits | Gigabits | Terabits | Percent | Count | Bytes/Second |
	// Kilobytes/Second | Megabytes/Second | Gigabytes/Second | Terabytes/Second | Bits/Second |
	// Kilobits/Second | Megabits/Second | Gigabits/Second | Terabits/Second | Count/Second | None
	Unit string
}

type MetricValue struct {
	Metric
	Value int
}

const (
	UnitBytes = "Bytes"
	// UnitSeconds      = "Seconds"
	// UnitMicroseconds = "Microseconds"
	// UnitMilliseconds = "Milliseconds"
)

// Each Dimension must have its name in at least one DimensionSet
type Dimension struct {
	Name  string
	Value string
}

// A Logger conveniently stores repeatedly used embedded metric format configurations such as
// namespace and dimensions so that they do not need to be initialized each time.
type Logger struct {
	namespace  string
	dimensions []DimensionSet
}

// MustLogger creates a new Logger based on the given input, and panics if the input is invalid
func MustLogger(namespace string, dimensions []DimensionSet) *Logger {
	logger, err := NewLogger(namespace, dimensions)
	if err != nil {
		panic(err)
	}
	return logger
}

// NewLogger create a new logger for a given namespace and set of dimensions, returning an error if
// the namespace or dimensions are invalid
func NewLogger(namespace string, dimensions []DimensionSet) (*Logger, error) {
	if namespace == "" || dimensions == nil {
		return nil, errors.New("namespace and dimension cannot be empty")
	}
	return &Logger{
		namespace:  namespace,
		dimensions: dimensions,
	}, nil
}

// Log sends a log formatted in the CloudWatch embedded metric format
func (l *Logger) Log(values map[Metric]interface{}, dimensions map[string]string) {
	err := LogEmbedded(l.namespace, values, dimensions, l.dimensions)
	if err != nil {
		zap.L().Error("metric failed", zap.Error(err))
	}
}

// LogEmbedded constructs an object in the AWS embedded metric format and logs it
func LogEmbedded(namespace string, values map[Metric]interface{},
	dimensions map[string]string, dimensionSets []DimensionSet) error {
	// Validate input
	if namespace == "" {
		return errors.New("namespace is required")
	}
	if len(values) == 0 || len(dimensions) == 0 || len(dimensionSets) == 0 {
		return errors.New("values, dimensions, and dimensionSets cannot be empty")
	}

	if len(values) > maxMetricsPerDirective {
		return errors.New("max number of metrics exceeded")
	}

	timestamp := time.Now().UnixNano() / 1000000 // Nanosecond -> Millisecond conversion

	for _, dimensionSet := range dimensionSets {
		for _, dimensionKey := range dimensionSet {
			if _, ok := dimensions[dimensionKey]; !ok {
				return errors.New("missing value for dimension field " + dimensionKey)
			}
		}
	}

	// Add each dimension to the list of top level fields
	fields := make([]zap.Field, 0, len(dimensions)+len(values)+1)
	for dimensionKey, dimensionValue := range dimensions {
		fields = append(fields, zap.Field{
			Key:    dimensionKey,
			String: dimensionValue,
		})
	}

	// Add each metric value to both the list of metrics and the list of top level fields
	metrics := make([]Metric, 0, len(values))
	for metric, metricValue := range values {
		fields = append(fields, zap.Field{
			Key:       metric.Name,
			Interface: metricValue,
		})
		metrics = append(metrics, metric)
	}

	// Construct the embedded metric metadata object per AWS standards
	// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
	embeddedMetric := EmbeddedMetric{
		CloudWatchMetrics: []MetricDirectiveObject{
			{
				Namespace:  namespace,
				Dimensions: dimensionSets,
				Metrics:    metrics,
			},
		},
		Timestamp: timestamp,
	}

	fields = append(fields, zap.Field{
		Key:       "_aws",
		Interface: embeddedMetric,
	})

	zap.L().Info("metric", fields...)
	return nil
}

// A MonoLogger conveniently stores repeatedly used embedded metric format configurations such as
// namespace and dimensions so that they do not need to be initialized each time. MonoLogger only
// supports one dimension set and one metric unit which must be set at initialization.
//
// These limitations still allow for 90% of use cases, and are suitable for more performance
// critical parts of the code.
type MonoLogger struct {
	directive []MetricDirectiveObject
}

// MustLogger creates a new Logger based on the given input, and panics if the input is invalid
func MustMonoLogger(namespace string, dimensionSet DimensionSet, metric Metric) *MonoLogger {
	logger, err := NewMonoLogger(namespace, dimensionSet, metric)
	if err != nil {
		panic(err)
	}
	return logger
}

// NewLogger create a new logger for a given namespace and set of dimensions, returning an error if
// the namespace or dimensions are invalid
func NewMonoLogger(namespace string, dimensionSet DimensionSet, metric Metric) (*MonoLogger, error) {
	if namespace == "" || metric.Name == "" || metric.Unit == "" {
		return nil, errors.New("namespace, metric name, and metric unit cannot be empty")
	}

	// Enforced by AWS specification
	if len(dimensionSet) > maxDimensionsKeys {
		return nil, errors.New("max dimensions exceeded")
	}

	directive := []MetricDirectiveObject{
		{
			Namespace:  namespace,
			Dimensions: []DimensionSet{dimensionSet},
			Metrics:    []Metric{metric},
		},
	}

	// Don't include any of the dimensionSet boilerplate if there are no dimensions
	if dimensionSet == nil {
		directive[0].Dimensions = nil
	}

	return &MonoLogger{
		directive: directive,
	}, nil
}

// Log sends a log formatted in the CloudWatch embedded metric format
func (l *MonoLogger) Log(value interface{}, dimensions ...Dimension) {
	fastLogEmbedded(l.directive, value, dimensions...)
}

// fastLogEmbedded seeks to minimize safety checking and allocations by front loading validation in
// the logger instantiation and limiting inputs to one metric value and one dimension set.
func fastLogEmbedded(directive []MetricDirectiveObject, value interface{}, dimensions ...Dimension) {
	// Set timestamp to current time
	timestamp := time.Now().UnixNano() / 1000000 // Nanosecond -> Millisecond conversion

	// Flying without a net, we skip validating the dimensions

	// Add each dimension to the list of top level fields
	fields := make([]zap.Field, 0, len(dimensions)+2) // +1 for the metric value, +1 for the _aws node
	for _, dimension := range dimensions {
		fields = append(fields, zap.String(dimension.Name, dimension.Value))
	}

	// Add the only metric name & value
	fields = append(fields, zap.Any(directive[0].Metrics[0].Name, value))

	// Construct the embedded metric metadata object per AWS standards
	// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
	embeddedMetric := EmbeddedMetric{
		CloudWatchMetrics: directive,
		Timestamp:         timestamp,
	}

	fields = append(fields, zap.Any("_aws", embeddedMetric))

	zap.L().Info("metric", fields...)
}
