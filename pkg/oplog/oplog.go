/*
Package oplog implements standard (but extensible) logging for operations (events with status, start/end times).
Useful for operational queries and dashboarding with CloudWatch Insights/Metrics. Using standard attributes
describing operations and their status allows easy creation of Cloudwatch alarms for discrete system operations.
The 3 level (namespace, component, operation) hierarchy enables grouping when graphing/querying. For
example, if the hierarchy has top level namespace of "logprocessor" then you can see all errors
where namespace="logprocessor" in single graph/query. Similarly you can compute latency and other
performance related metrics in aggregate over different _standard_ dimensions.

Example usage:

  manager := oplog.NewManager("panther", "logprocessor")
  // record every S3 object read
  operation := manager.Start("readlogfile")
  defer func() {
		operation.Stop()
        operation.Log(err,
           zap.String("bucket", bucket),
           zap.String("object", object))
  }()
  ... code to read log from S3

*/
package oplog

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
	"runtime"
	"time"

	"go.uber.org/zap"
)

/* TODO: Consider emitting CW embedded metric format also:
https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
*/

const (
	Success = "success"
	Failure = "failure"
)

type Manager struct {
	Namespace string
	Component string
}

func NewManager(namespace, component string) *Manager {
	return &Manager{
		Namespace: namespace,
		Component: component,
	}
}

type Operation struct {
	Manager        *Manager
	Name           string
	Dimensions     []zap.Field
	StartTime      time.Time
	EndTime        time.Time
	StartMemStats  *runtime.MemStats // can be nil!
	EndMemStats    *runtime.MemStats // can be nil!
	AvailableMemMB int               // if not zero, the available memory, use to calc percentage
}

func (m *Manager) Start(operation string, dimensions ...zap.Field) *Operation {
	return &Operation{
		Manager:    m,
		Name:       operation,
		Dimensions: dimensions,
		StartTime:  time.Now().UTC(),
	}
}

func (o *Operation) WithMemStats() *Operation {
	if o.StartMemStats == nil {
		o.StartMemStats = &runtime.MemStats{}
		runtime.ReadMemStats(o.StartMemStats) // record where we are starting
	}
	return o
}

func (o *Operation) WithMemUsed(availableMemMB int) *Operation {
	o.WithMemStats()
	o.AvailableMemMB = availableMemMB
	return o
}

func (o *Operation) Stop() *Operation {
	o.EndTime = time.Now().UTC()
	o.EndMemStats = &runtime.MemStats{}
	runtime.ReadMemStats(o.EndMemStats) // record where we are ending
	return o
}

func (o *Operation) zapMsg() string {
	return o.Manager.Namespace + ":" + o.Manager.Component + ":" + o.Name
}

func (o *Operation) fields(status string) []zap.Field {
	return append(o.standardFields(status), o.Dimensions...)
}

func (o *Operation) standardFields(status string) (fields []zap.Field) {
	var dur time.Duration
	if o.EndTime.IsZero() { // operation is still going
		dur = time.Since(o.StartTime)
	} else {
		dur = o.EndTime.Sub(o.StartTime)
	}
	fields = []zap.Field{
		zap.String("namespace", o.Manager.Namespace),
		zap.String("component", o.Manager.Component),
		zap.String("operation", o.Name),
		zap.String("status", status),
		zap.Time("startOp", o.StartTime),
		zap.Duration("opTime", dur),
	}
	if !o.EndTime.IsZero() {
		fields = append(fields, zap.Time("endOp", o.EndTime))
	}
	if o.StartMemStats != nil && o.EndMemStats != nil {
		fields = append(fields, zap.Uint64("sysSizeMB",
			o.EndMemStats.Sys/(1024*1024))) // for all time until now
		fields = append(fields, zap.Uint64("heapSizeMB",
			o.EndMemStats.HeapAlloc/(1024*1024))) // for all time until now
		fields = append(fields, zap.Int64("heapChangeMB",
			(int64(o.EndMemStats.HeapAlloc)-int64(o.StartMemStats.HeapAlloc))/(1024*1024))) // signed cuz could go down!
		fields = append(fields, zap.Float64("gcPercent",
			o.EndMemStats.GCCPUFraction)) // for all time until now
		fields = append(fields, zap.Uint64("gcPauseMilliseconds",
			(o.EndMemStats.PauseTotalNs-o.StartMemStats.PauseTotalNs)/1000000))
		fields = append(fields, zap.Uint32("gcCycles",
			o.EndMemStats.NumGC-o.StartMemStats.NumGC))
	}
	if o.AvailableMemMB > 0 && o.EndMemStats != nil {
		percentMemUsed := int(((float32)(o.EndMemStats.Sys / (1024 * 1024))) / (float32)(o.AvailableMemMB) * 100.0)
		if percentMemUsed > 100 { // this can happen because Stats.Sys includes virtual mappings, makes graphs look silly
			percentMemUsed = 100
		}
		fields = append(fields, zap.Int("percentMemUsed", percentMemUsed)) // for all time until now
	}
	return fields
}

// wrapper handling err
func (o *Operation) Log(err error, fields ...zap.Field) {
	if err != nil {
		o.LogError(err, fields...)
	} else {
		o.LogSuccess(fields...)
	}
}

func (o *Operation) LogSuccess(fields ...zap.Field) {
	zap.L().Info(o.zapMsg(), append(fields, o.fields(Success)...)...)
}

// implies status=Fail
func (o *Operation) LogWarn(err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	zap.L().Warn(o.zapMsg(), append(fields, o.fields(Failure)...)...)
}

// implies status=Fail
func (o *Operation) LogError(err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	zap.L().Error(o.zapMsg(), append(fields, o.fields(Failure)...)...)
}

// Errors which are good to know about, but do not need to trigger ops alarms from Warn/Error log msgs
func (o *Operation) LogNonCriticalError(err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	zap.L().Info(o.zapMsg(), append(fields, o.fields(Failure)...)...)
}
