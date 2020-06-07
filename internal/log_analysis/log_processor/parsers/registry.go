package parsers

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
	"net/url"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// Default registry for pantherlog package
var defaultRegistry = &Registry{}

// DefaultRegistry returns the default package wide registry for log types
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Register registers log type entries to the package wide registry returning the first error it encounters
func Register(entries ...LogTypeConfig) error {
	for _, entry := range entries {
		if _, err := defaultRegistry.Register(entry); err != nil {
			return err
		}
	}
	return nil
}

// Register registers log type entries to the package wide registry panicking if an error occurs
func MustRegister(entries ...LogTypeConfig) {
	for _, entry := range entries {
		// nolint:errcheck
		DefaultRegistry().MustRegister(entry)
	}
}

// LogTypeEntry describes a registered log event type.
// It provides a method to create a new parser and a schema struct to derive tables from.
// Entries can be grouped in a `Registry` to have an index of available log types.
type LogTypeEntry interface {
	Describe() Desc
	NewParser(params interface{}) pantherlog.LogParser
	Schema() interface{}
	GlueTableMeta() *awsglue.GlueTableMetadata
}

// LogTypeConfig describes a log event type in a declarative way.
// To convert to a LogTypeEntry instance it must be registered.
// The LogTypeConfig/LogTypeEntry separation enforces mutability rules for registered log event types.
type LogTypeConfig struct {
	Name         string
	Description  string
	ReferenceURL string
	Schema       interface{}
	NewParser    pantherlog.LogParserFactory
}

func (config *LogTypeConfig) Describe() Desc {
	return Desc{
		Name:         config.Name,
		Description:  config.Description,
		ReferenceURL: config.ReferenceURL,
	}
}

// Check verifies a log type is valid
func (config *LogTypeConfig) Validate() error {
	if config == nil {
		return errors.Errorf("nil log event type config")
	}
	desc := config.Describe()
	if err := desc.Validate(); err != nil {
		return err
	}
	if err := checkLogEntrySchema(desc.Name, config.Schema); err != nil {
		return err
	}
	return nil
}

func checkLogEntrySchema(logType string, schema interface{}) error {
	if schema == nil {
		return errors.Errorf("nil schema for log type %q", logType)
	}
	data, err := jsoniter.Marshal(schema)
	if err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	var fields map[string]interface{}
	if err := jsoniter.Unmarshal(data, &fields); err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	return nil
}

// Desc describes an registered log type.
type Desc struct {
	Name         string
	Description  string
	ReferenceURL string
}

func (desc *Desc) Validate() error {
	if desc.Name == "" {
		return errors.Errorf("missing entry log type")
	}
	if desc.Description == "" {
		return errors.Errorf("missing description for log type %q", desc.Name)
	}
	if desc.ReferenceURL == "" {
		return errors.Errorf("missing reference URL for log type %q", desc.Name)
	}
	if desc.ReferenceURL != "-" {
		u, err := url.Parse(desc.ReferenceURL)
		if err != nil {
			return errors.Wrapf(err, "invalid reference URL for log type %q", desc.Name)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			return errors.Wrapf(err, "invalid reference URL scheme %q for log type %q", u.Scheme, desc.Name)
		}
	}
	return nil
}

// Registry is a collection of log type entries.
// It is safe to use a registry from multiple goroutines.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]LogTypeEntry
}

// MustGet gets a registered LogTypeConfig or panics
func (r *Registry) MustGet(name string) LogTypeEntry {
	if logType := r.Get(name); logType != nil {
		return logType
	}
	panic(errors.Errorf("unregistered log type %q", name))
}

// Get returns finds an LogTypeConfig entry in a registry.
// The returned pointer should be used as a *read-only* share of the LogTypeConfig.
func (r *Registry) Get(name string) LogTypeEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// Entries returns EventType entries in a registry.
// If no names are provided all entries are returned.
func (r *Registry) Entries(names ...string) []LogTypeEntry {
	if names == nil {
		names = r.LogTypes()
	}
	m := make([]LogTypeEntry, 0, len(names))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, name := range names {
		if entry := r.entries[name]; entry != nil {
			m = append(m, entry)
		}
	}
	return m
}
func (r *Registry) Parsers(params map[string]interface{}) map[string]pantherlog.LogParser {
	parsers := make(map[string]pantherlog.LogParser, len(params))
	r.mu.Lock()
	defer r.mu.Unlock()
	for logType, params := range params {
		if entry := r.entries[logType]; entry != nil {
			parsers[logType] = entry.NewParser(params)
		}
	}
	return parsers
}

// LogTypes returns all available log types in a registry
func (r *Registry) LogTypes() (logTypes []string) {
	const minLogTypesSize = 32
	logTypes = make([]string, 0, minLogTypesSize)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for logType := range r.entries {
		logTypes = append(logTypes, logType)
	}
	return
}

// Each calls a function for each LogTypeConfig entry in the registry
func (r *Registry) Each(fn func(entry LogTypeEntry)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entry := range r.entries {
		fn(entry)
	}
}

func (r *Registry) Del(entry LogTypeEntry) bool {
	if entry == nil {
		return false
	}
	name := entry.Describe().Name
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[name]; ok && e == entry {
		delete(r.entries, name)
		return true
	}
	return false
}

func (r *Registry) Register(config LogTypeConfig) (LogTypeEntry, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	newEntry := newLogEventType(config.Describe(), config.Schema, config.NewParser)
	r.mu.Lock()
	defer r.mu.Unlock()
	if oldEntry, duplicate := r.entries[newEntry.Name]; duplicate {
		return oldEntry, errors.Errorf("duplicate log type config %q", newEntry.Name)
	}
	if r.entries == nil {
		r.entries = make(map[string]LogTypeEntry)
	}
	r.entries[newEntry.Name] = newEntry
	return newEntry, nil
}

func (r *Registry) MustRegister(config LogTypeConfig) LogTypeEntry {
	entry, err := r.Register(config)
	if err != nil {
		panic(err)
	}
	return entry
}

type logEventType struct {
	Desc
	schema        interface{}
	newParser     pantherlog.LogParserFactory
	glueTableMeta *awsglue.GlueTableMetadata
}

func newLogEventType(desc Desc, schema interface{}, fac pantherlog.LogParserFactory) *logEventType {
	return &logEventType{
		Desc:          desc,
		schema:        schema,
		newParser:     fac,
		glueTableMeta: awsglue.NewGlueTableMetadata(models.LogData, desc.Name, desc.Description, awsglue.GlueTableHourly, schema),
	}
}

func (e *logEventType) Describe() Desc {
	return e.Desc
}
func (e *logEventType) Schema() interface{} {
	return e.schema
}

func (e *logEventType) GlueTableMeta() *awsglue.GlueTableMetadata {
	return e.glueTableMeta
}

// Parser returns a new LogParser instance for this log type
func (e *logEventType) NewParser(params interface{}) pantherlog.LogParser {
	return e.newParser(params)
}
