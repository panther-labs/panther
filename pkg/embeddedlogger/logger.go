package embeddedlogger

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

type EmbeddedMetric struct {
	CloudWatchMetrics []MetricDirectiveObject
	Timestamp         int64
}

type MetricDirectiveObject struct {
	Namespace  string
	Dimensions [][]string
	Metrics    []Metric
}

type Metric struct {
	Name string
	Unit string
}

type Logger struct {
	namespace  string
	dimensions [][]string
}

// Create a new logger for a given namespace and set of dimensions
func NewLogger(namespace string, dimensions [][]string) (*Logger, error) {
	if namespace == "" || dimensions == nil {
		return nil, errors.New("namespace and dimension cannot be empty")
	}
	return &Logger{
		namespace:  namespace,
		dimensions: dimensions,
	}, nil
}

// Log sends a log to the CloudWatch log group formatted in the CloudWatch embedded metric format
func (l *Logger) Log(values map[Metric]interface{}, dimensions map[string]string) error {
	return LogEmbedded(l.namespace, values, dimensions, l.dimensions, 0)
}

// LogEmbedded constructs an object in the AWS embedded metric format and logs it
func LogEmbedded(namespace string, values map[Metric]interface{},
	dimensions map[string]string, dimensionSets [][]string, timestamp int64) error {
	// Validate input
	if namespace == "" {
		return errors.New("namespace is required")
	}
	if len(values) == 0 || len(dimensions) == 0 || len(dimensionSets) == 0 {
		return errors.New("values, dimensions, and dimensionSets cannot be empty")
	}

	// Set timestamp to current time if one is not provided
	if timestamp == 0 {
		timestamp = time.Now().UnixNano() / 1000000
	}

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
