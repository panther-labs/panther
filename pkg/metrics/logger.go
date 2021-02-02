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

// EmbeddedMetric is the value mapped to the required top level member of the root node `_aws` in
// the AWS embedded metric format.
type EmbeddedMetric struct {
	// A slice of MetricDirectiveObjects used to instruct CloudWatch to extract metrics from the
	// root node of the LogEvent.
	CloudWatchMetrics []MetricDirectiveObject

	// A number representing the time stamp used for metrics extracted from the event. Values MUST
	// be expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
	Timestamp int64
}

// The standard go time library supports nanoseconds since epoch time, not milliseconds. So we
// frequently convert.
const NanosecondsPerMillisecond int64 = 1000000

// MetricDirectiveObject instructs downstream services that the LogEvent contains metrics that
// will be extracted and published to CloudWatch.
type MetricDirectiveObject struct {
	// A string representing the CloudWatch namespace for the metric.
	Namespace string

	// A slice representing the collection of DimensionSets for the metric
	Dimensions []DimensionSet

	// A slice of Metric values and units. This slice MUST NOT contain more than 100 Metrics.
	Metrics []Metric
}

const (
	// Per the AWS specification, a single metric directive can have at most 100 metric values
	maxMetricsPerDirective = 100
	Namespace              = "Panther"
)

// DimensionSet is a slice of strings containing the dimension names that will be applied to all
// metrics logged. The values within this slice MUST also be members on the root node, referred to
// as the Target Members
//
// A DimensionSet MUST NOT contain more than 9 dimension keys.
//
// The target member defines a dimension that will be published as part of the metric identity.
// Every DimensionSet used creates a new metric in CloudWatch.
type DimensionSet = []string

// Per the AWS specification, a single dimension set can have at most 9 keys.
const maxDimensionsKeys = 9

// Metric contains a name and a unit used to describe a particular metric value
type Metric struct {
	// A reference to a metric Target Member. Each Metric Name must also be a top level member.
	Name string

	// Valid Unit values (defaults to None):
	// Seconds | Microseconds | Milliseconds | Bytes | Kilobytes | Megabytes | Gigabytes | Terabytes
	// Bits | Kilobits | Megabits | Gigabits | Terabits | Percent | Count | Bytes/Second |
	// Kilobytes/Second | Megabytes/Second | Gigabytes/Second | Terabytes/Second | Bits/Second |
	// Kilobits/Second | Megabits/Second | Gigabits/Second | Terabits/Second | Count/Second | None
	Unit string

	// This value is not marshalled to JSON as it is not part of the AWS embedded metric format. We
	// simply include it here for convenience when calling the loggers defined here, so that it is
	// not required to consider the value of a metric separate from its Name and Unit.
	Value interface{} `json:"-"`
}

// Values that AWS understands as Metric Units
const (
	UnitBytes   = "Bytes"
	UnitSeconds = "Seconds"
	// UnitMicroseconds = "Microseconds"
	UnitMilliseconds = "Milliseconds"
	UnitCount        = "Count"
)

// Dimension represents the name and value of a given dimension. Each dimension must have its name
// in at least one DimensionSet to be recognized as a dimension.
type Dimension struct {
	Name  string
	Value string
}

type Logger interface {
	Log(dimensions []Dimension, values ...Metric)
}

// Logger conveniently stores repeatedly used embedded metric format configurations such as
// dimensions so that they do not need to be specified for each log.
type logger struct {
	dimensionSets []DimensionSet
	dimensionKeys map[string]struct{}
}

// MustLogger creates a new Logger based on the given input, and panics if the input is invalid
func MustLogger(dimensionSets []DimensionSet) Logger {
	logger, err := NewLogger(dimensionSets)
	if err != nil {
		panic(err)
	}
	return logger
}

// NewLogger create a new logger for a set of dimensions, returning an error if dimensions are invalid
func NewLogger(dimensionSets []DimensionSet) (Logger, error) {
	dimensionKeys, err := buildDimensionKeys(dimensionSets)
	if err != nil {
		return nil, err
	}

	return &logger{
		dimensionSets: dimensionSets,
		dimensionKeys: dimensionKeys,
	}, nil
}

// Log sends a log formatted in the CloudWatch embedded metric format
func (l *logger) Log(dimensions []Dimension, values ...Metric) {
	err := l.logEmbedded(dimensions, values...)
	if err != nil {
		zap.L().Error("metric failed", zap.Error(err))
	}
}

// logEmbedded constructs an object in the AWS embedded metric format and logs it
func (l *logger) logEmbedded(dimensions []Dimension, values ...Metric) error {
	// Validate input
	if len(values) == 0 {
		return errors.New("at least one metric must be specified")
	}

	if len(values) > maxMetricsPerDirective {
		return errors.New("max number of metrics exceeded")
	}

	timestamp := time.Now().UnixNano() / NanosecondsPerMillisecond

	if err := validateDimensions(l.dimensionKeys, dimensions); err != nil {
		return err
	}

	// Add each dimension to the list of top level fields
	fields := make([]zap.Field, 0, len(dimensions)+len(values)+1)
	for _, dimension := range dimensions {
		fields = append(fields, zap.String(dimension.Name, dimension.Value))
	}

	// Add each metric value to both the list of metrics and the list of top level fields
	metrics := make([]Metric, 0, len(values))
	for _, metric := range values {
		fields = append(fields, zap.Any(metric.Name, metric.Value))
		metrics = append(metrics, metric)
	}

	// Construct the embedded metric metadata object per AWS standards
	// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
	embeddedMetric := EmbeddedMetric{
		CloudWatchMetrics: []MetricDirectiveObject{
			{
				Namespace:  Namespace,
				Dimensions: l.dimensionSets,
				Metrics:    metrics,
			},
		},
		Timestamp: timestamp,
	}

	const rootElement = "_aws"
	fields = append(fields, zap.Any(rootElement, embeddedMetric))

	const metricField = "metric"
	zap.L().Info(metricField, fields...)
	return nil
}

// StaticLogger conveniently stores repeatedly used embedded metric format configurations such as
// dimensionSets and metric name/unit so that they do not need to be specified each time. StaticLogger
// only supports one dimension set and one metric which must be set at initialization.
//
// These limitations still allow for 90% of use cases, and are more suitable for performance
// critical parts of the code than the Logger.
type StaticLogger struct {
	directive     []MetricDirectiveObject
	dimensionKeys map[string]struct{}
	metricKeys    map[string]struct{}
}

// MustStaticLogger creates a new StaticLogger based on the given input, and panics if the input is invalid
func MustStaticLogger(dimensionSets []DimensionSet, metrics []Metric) *StaticLogger {
	logger, err := NewStaticLogger(dimensionSets, metrics)
	if err != nil {
		panic(err)
	}
	return logger
}

// NewStaticLogger create a new logger for a given set of dimensions and metric, returning an error if
// the dimensions or metric are invalid
func NewStaticLogger(dimensionSets []DimensionSet, metrics []Metric) (*StaticLogger, error) {
	if len(metrics) > maxMetricsPerDirective {
		return nil, errors.New("max number of metrics exceeded")
	}

	for _, metric := range metrics {
		if metric.Name == "" || metric.Unit == "" {
			return nil, errors.New("metric name and metric unit cannot be empty")
		}
	}

	dimensionKeys, err := buildDimensionKeys(dimensionSets)
	if err != nil {
		return nil, err
	}

	metricKeys := make(map[string]struct{}, len(metrics))
	for _, metric := range metrics {
		metricKeys[metric.Name] = struct{}{}
	}

	directive := []MetricDirectiveObject{
		{
			Namespace:  Namespace,
			Dimensions: dimensionSets,
			Metrics:    metrics,
		},
	}

	return &StaticLogger{
		directive:     directive,
		dimensionKeys: dimensionKeys,
		metricKeys:    metricKeys,
	}, nil
}

// Log sends a log formatted in the CloudWatch embedded metric format
func (l *StaticLogger) Log(metrics []Metric, dimensions ...Dimension) {
	err := l.staticLogEmbedded(metrics, dimensions...)
	if err != nil {
		zap.L().Error("metric failed", zap.Error(err))
	}
}

// LogSingle sends a log for a single metric
func (l *StaticLogger) LogSingle(value interface{}, dimensions ...Dimension) {
	err := l.staticLogEmbedded([]Metric{{
		Name:  l.directive[0].Metrics[0].Name,
		Value: value,
	}}, dimensions...)
	if err != nil {
		zap.L().Error("metric failed", zap.Error(err))
	}
}

// fastLogEmbedded seeks to simplify safety checking and minimize allocations by front loading
// validation in the logger instantiation and limiting inputs to one metric value and one dimension set.
func (l *StaticLogger) staticLogEmbedded(metrics []Metric, dimensions ...Dimension) error {
	// Set timestamp to current time
	timestamp := time.Now().UnixNano() / NanosecondsPerMillisecond

	// Validate the dimensions provided match the dimensions required
	if err := validateDimensions(l.dimensionKeys, dimensions); err != nil {
		return err
	}

	// Validate the metrics provided match the metrics required
	if err := validateMetrics(l.metricKeys, metrics); err != nil {
		return err
	}

	// Add each dimension
	fields := make([]zap.Field, 0, len(dimensions)+len(metrics)+1) // +1 for the _aws node
	for _, dimension := range dimensions {
		fields = append(fields, zap.String(dimension.Name, dimension.Value))
	}

	// Add each metric
	for _, metric := range metrics {
		fields = append(fields, zap.Any(metric.Name, metric.Value))
	}

	// Construct the embedded metric metadata object per AWS standards
	// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
	embeddedMetric := EmbeddedMetric{
		CloudWatchMetrics: l.directive,
		Timestamp:         timestamp,
	}

	fields = append(fields, zap.Any("_aws", embeddedMetric))

	zap.L().Info("metric", fields...)
	return nil
}

// validateDimensions takes a set of required dimensions and a slice of dimension structs and
// verifies that each required key is present in the list of provided dimensions. Unfortunately
// checking the inverse is not sufficient or this would be simpler.
func validateDimensions(dimensionKeys map[string]struct{}, dimensions []Dimension) error {
	for dimensionKey := range dimensionKeys {
		found := false
		for _, dimension := range dimensions {
			if dimension.Name == dimensionKey {
				found = true
				break
			}
		}
		if !found {
			return errors.New("missing value for dimension field " + dimensionKey)
		}
	}
	return nil
}

// buildDimensionKeys creates a set of each unique dimension name found a slice of DimensionSets.
// This map is used to more easily verify that all the required dimensions are present for each call
// to Log.
func buildDimensionKeys(dimensionSets []DimensionSet) (map[string]struct{}, error) {
	dimensionKeys := make(map[string]struct{})
	for _, dimensionSet := range dimensionSets {
		// Enforced by AWS specification
		if len(dimensionSet) > maxDimensionsKeys {
			return nil, errors.New("max dimensions exceeded for a single dimension set")
		}
		for _, dimension := range dimensionSet {
			dimensionKeys[dimension] = struct{}{}
		}
	}
	return dimensionKeys, nil
}

// validateMetrics takes a set of required metric names and a slice of metric structs and
// verifies that each required name is present in the list of provided metrics. Unfortunately
// checking the inverse is not sufficient or this would be simpler.
func validateMetrics(metricNames map[string]struct{}, metrics []Metric) error {
	for metricName := range metricNames {
		found := false
		for _, metric := range metrics {
			if metric.Name == metricName {
				found = true
				break
			}
		}
		if !found {
			return errors.New("missing value for metric " + metricName)
		}
	}
	return nil
}
