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
	"fmt"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

// LogType decsribes a log type.
// It provides a method to create a new parser and a schema struct to derive
// tables from. LogTypes can be grouped in a `Registry` to have an index of available
// log types.
type LogType struct {
	Name        string
	Description string
	Schema      interface{}
	NewParser   ParserFactory
}

// ParserFactory creates a new parser instance.
type ParserFactory func() Interface

// GlueTableMetadata returns metadata about the glue table based on LogType.Schema
func (entry *LogType) GlueTableMetadata() *awsglue.GlueTableMetadata {
	return awsglue.NewLogTableMetadata(entry.Name, entry.Description, entry.Schema)
}

func (entry *LogType) Check() error {
	if entry == nil {
		return errors.Errorf("nil log type entry")
	}
	if entry.Name == "" {
		return errors.Errorf("missing entry log type")
	}
	if entry.Description == "" {
		return errors.Errorf("missing description for log type %q", entry.Name)
	}
	// describes Glue table over processed data in S3
	// assert it does not panic here until some validation method is provided
	// TODO: [awsglue] Add some validation for the metadata in `awsglue` package
	_ = awsglue.NewLogTableMetadata(entry.Name, entry.Description, entry.Schema)

	return checkLogEntrySchema(entry.Name, entry.Schema)
}

// Registry is a collection of LogTypes.
// It is safe to use a registry from multiple go routines.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*LogType
}

func NewRegistry(logTypes ...LogType) (*Registry, error) {
	r := &Registry{}
	for _, logType := range logTypes {
		if err := r.Register(logType); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// MustGet gets a registered LogType or panics
func (r *Registry) MustGet(name string) *LogType {
	if logType := r.Get(name); logType != nil {
		return logType
	}
	panic(fmt.Sprintf("unregistered log type %q", name))
}

func (r *Registry) Get(name string) *LogType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// LogTypes returns all available log types in a registry
func (r *Registry) LogTypes() (logTypes []LogType) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, logType := range r.entries {
		logTypes = append(logTypes, *logType)
	}
	return
}

func (r *Registry) Register(entry LogType) error {
	if err := entry.Check(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, duplicate := r.entries[entry.Name]; duplicate {
		return errors.Errorf("duplicate log type entry %q", entry.Name)
	}
	if r.entries == nil {
		r.entries = make(map[string]*LogType)
	}
	r.entries[entry.Name] = &entry
	return nil
}

// Default registry for parsers package
var defaultRegistry = &Registry{}

// DefaultRegistry returns the default package wide registry for log types
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Get gets a LogType entry from the package wide registry
func Get(logType string) *LogType {
	return defaultRegistry.Get(logType)
}

// MustGet gets a LogType entry from the package wide registry and panics if `logType` is not registered
func MustGet(logType string) *LogType {
	return defaultRegistry.MustGet(logType)
}

// Register registers log type entries to the package wide registry returning the first error it encounters
func Register(entries ...LogType) error {
	for _, entry := range entries {
		if err := defaultRegistry.Register(entry); err != nil {
			return err
		}
	}
	return nil
}

// Register registers log type entries to the package wide registry panicking if an error occurs
func MustRegister(entries ...LogType) {
	if err := Register(entries...); err != nil {
		panic(err)
	}
}

// Available log types returns the available log types
func AvailableLogTypes() []LogType {
	return defaultRegistry.LogTypes()
}

// NewParser returns a new parser interface for a registered log type
func NewParser(logType string) (Interface, error) {
	entry := defaultRegistry.Get(logType)
	if entry != nil {
		return entry.NewParser(), nil
	}
	return nil, errors.Errorf("unregistered LogType %q", logType)
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
	// TODO: [parsers] Use reflect to check provided schema struct for required panther fields
	return nil
}
