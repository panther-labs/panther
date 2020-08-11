package logtypes

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// Registry is a collection of log type entries.
// It is safe to use a registry from multiple goroutines.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// MustGet gets a registered LogTypeConfig or panics
func (r *Registry) MustGet(name string) Entry {
	if entry := r.Get(name); entry != nil {
		return entry
	}
	panic(errors.Errorf("unregistered log type %q", name))
}

// Get returns finds an LogTypeConfig entry in a registry.
// The returned pointer should be used as a *read-only* share of the LogTypeConfig.
func (r *Registry) Get(name string) Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// Entries returns log type entries in a registry.
// If no names are provided all entries are returned.
func (r *Registry) Entries(names ...string) []Entry {
	if names == nil {
		names = r.LogTypes()
	}
	m := make([]Entry, 0, len(names))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, name := range names {
		if entry := r.entries[name]; entry != nil {
			m = append(m, entry)
		}
	}
	return m
}

// LogTypes returns all available log types in a registry
func (r *Registry) LogTypes() (logTypes []string) {
	// Avoid allocation under lock
	const minLogTypesSize = 32
	logTypes = make([]string, 0, minLogTypesSize)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for logType := range r.entries {
		logTypes = append(logTypes, logType)
	}
	return
}

func (r *Registry) Del(logType string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[logType]; ok {
		delete(r.entries, logType)
		return true
	}
	return false
}

func (r *Registry) RegisterJSON(desc Desc, eventFactory func() interface{}) (Entry, error) {
	if eventFactory == nil {
		return nil, errors.New(`nil event factory`)
	}
	event := eventFactory()
	schema, err := pantherlog.BuildEventSchema(event)
	if err != nil {
		return nil, err
	}
	config := Config{
		Name:         desc.Name,
		Description:  desc.Description,
		ReferenceURL: desc.ReferenceURL,
		Schema:       schema,
		NewParser: &parsers.JSONParserFactory{
			LogType:  desc.Name,
			NewEvent: eventFactory,
		},
	}
	return r.Register(config)
}

func (r *Registry) Register(config Config) (Entry, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	newEntry := newEntry(config.Describe(), config.Schema, config.NewParser)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]Entry)
	}
	if oldEntry, duplicate := r.entries[newEntry.Name]; duplicate {
		return oldEntry, errors.Errorf("duplicate log type config %q", newEntry.Name)
	}
	r.entries[newEntry.Name] = newEntry
	return newEntry, nil
}

func (r *Registry) MustRegister(config Config) Entry {
	entry, err := r.Register(config)
	if err != nil {
		panic(err)
	}
	return entry
}

// Entry describes a registered log event type.
// It provides a method to create a new parser and a schema struct to derive tables from.
// Entries can be grouped in a `Registry` to have an index of available log types.
type Entry interface {
	Describe() Desc
	NewParser(params parsers.SourceParams) (parsers.Interface, error)
	Schema() interface{}
	GlueTableMeta() *awsglue.GlueTableMetadata
}

// Config describes a log event type in a declarative way.
// To convert to an Entry instance it must be registered.
// The Config/Entry separation enforces mutability rules for registered log event types.
type Config struct {
	Name         string
	Description  string
	ReferenceURL string
	Schema       interface{}
	NewParser    parsers.Factory
}

func (config *Config) Describe() Desc {
	return Desc{
		Name:         config.Name,
		Description:  config.Description,
		ReferenceURL: config.ReferenceURL,
	}
}

// Validate verifies a log type is valid
func (config *Config) Validate() error {
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
	if config.NewParser == nil {
		return errors.New("nil parser factory")
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
			return errors.Errorf("invalid reference URL scheme %q for log type %q", u.Scheme, desc.Name)
		}
	}
	return nil
}

type entry struct {
	Desc
	schema        interface{}
	newParser     parsers.FactoryFunc
	glueTableMeta *awsglue.GlueTableMetadata
}

func newEntry(desc Desc, schema interface{}, fac parsers.Factory) *entry {
	return &entry{
		Desc:          desc,
		schema:        schema,
		newParser:     fac.NewParser,
		glueTableMeta: awsglue.NewGlueTableMetadata(models.LogData, desc.Name, desc.Description, awsglue.GlueTableHourly, schema),
	}
}

func (e *entry) Describe() Desc {
	return e.Desc
}
func (e *entry) Schema() interface{} {
	return e.schema
}

// GlueTableMeta returns the glue table metadata for this entry
func (e *entry) GlueTableMeta() *awsglue.GlueTableMetadata {
	return e.glueTableMeta
}

// Parser returns a new parsers.Interface instance for this log type
func (e *entry) NewParser(params parsers.SourceParams) (parsers.Interface, error) {
	return e.newParser(params)
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
	// Verify we can generate glue schema from the provided struct
	if err := checkGlue(schema); err != nil {
		return errors.Wrapf(err, "failed to infer Glue columns for %q", logType)
	}
	return nil
}

func checkGlue(schema interface{}) (err error) {
	defer func() {
		if e := recover(); e != nil {
			switch e := e.(type) {
			case error:
				err = e
			case string:
				err = errors.New(e)
			default:
				err = errors.Errorf(`panic %v`, e)
			}
		}
	}()
	cols, _ := awsglue.InferJSONColumns(schema, awsglue.GlueMappings...)
	if len(cols) == 0 {
		err = errors.New("empty columns")
	}
	return
}
