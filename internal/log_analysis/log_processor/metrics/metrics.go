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
	"os"

	"github.com/panther-labs/panther/pkg/metrics"
)

const (
	SubsystemLogProcessor             = "LogProcessor"
	MetricLogProcessorGetObject       = "GetObject"
	MetricLogProcessorBytesProcessed  = "BytesProcessed"
	MetricLogProcessorEventsProcessed = "EventsProcessed"
	MetricLogProcessorEventLatency    = "EventLatency"

	// StatusDimension indicating that a subsystem operation is well
	StatusOK = "OK"
	// StatusDimension indicating that a subsystem is experiencing authZ/N errors
	StatusAuthErr = "AuthErr"
	// StatusDimension indicating some general error with the subsystem
	StatusErr = "Err"
)

var (
	CWManager           metrics.Manager
	GetObject           metrics.Counter
	BytesProcessed      metrics.Counter
	EventsProcessed     metrics.Counter
	EventLatencySeconds metrics.Counter
)

func Setup() {
	CWManager = metrics.NewCWEmbeddedMetrics(os.Stdout)
	// System-health metrics
	GetObject = CWManager.NewCounter(MetricLogProcessorGetObject, metrics.UnitCount).
		With(metrics.SubsystemDimension, SubsystemLogProcessor)

	// Note that these don't have all the dimensions
	BytesProcessed = CWManager.NewCounter(MetricLogProcessorBytesProcessed, metrics.UnitBytes)
	EventsProcessed = CWManager.NewCounter(MetricLogProcessorEventsProcessed, metrics.UnitCount)
	EventLatencySeconds = CWManager.NewCounter(MetricLogProcessorEventLatency, metrics.UnitSeconds)
}
