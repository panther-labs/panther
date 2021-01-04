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
	"fmt"
	"net/url"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// Entry describes a log event type.
// It provides a method to create a new parser and a schema struct to derive tables from.
type Entry interface {
	Describe() Desc
	pantherlog.LogParserFactory
	Schema() interface{}
	String() string
	// Entry should be usable as an EntryBuilder that returns itself with no error
	EntryBuilder
	// Entry should implement Group for a single entry
	Group
}

// EntryBuilder builds a new entry.
// It is used by various entry configurations (Config, ConfigJSON).
type EntryBuilder interface {
	BuildEntry() (Entry, error)
}

// MustBuild builds an entry from an EntryBuilder or panics
func MustBuild(builder EntryBuilder) Entry {
	entry, err := builder.BuildEntry()
	if err != nil {
		panic(err)
	}
	return entry
}

// Desc describes a log type.
type Desc struct {
	Name         string
	Description  string
	ReferenceURL string
}

// Validate validates the fields describing a log type.
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

func (desc *Desc) Fill() {
	if desc.ReferenceURL == "" {
		desc.ReferenceURL = "-"
	}
	if desc.Description == "" {
		desc.Description = fmt.Sprintf("%s log type", desc.Name)
	}
}

// ConfigJSON is a configuration that creates a log type entry for a JSON log.
// The parser only handles the usual case where each JSON value produces a single pantherlog.Result.
type ConfigJSON struct {
	Name            string
	Description     string
	ReferenceURL    string
	NewEvent        func() interface{}
	Validate        func(interface{}) error
	JSON            jsoniter.API
	NextRowID       func() string
	Now             func() time.Time
	ExtraIndicators pantherlog.FieldSet
}

// BuildEntry implements EntryBuilder interface
func (c ConfigJSON) BuildEntry() (Entry, error) {
	if c.NewEvent == nil {
		return nil, errors.New(`nil event factory`)
	}

	event := c.NewEvent()
	schema, err := pantherlog.BuildEventSchema(event, c.ExtraIndicators...)
	if err != nil {
		return nil, err
	}
	config := Config{
		Name:         c.Name,
		Description:  c.Description,
		ReferenceURL: c.ReferenceURL,
		Schema:       schema,
		NewParser: &pantherlog.JSONParserFactory{
			LogType:   c.Name,
			JSON:      c.JSON,
			Validate:  c.Validate,
			NewEvent:  c.NewEvent,
			Now:       c.Now,
			NextRowID: c.NextRowID,
		},
	}
	return config.BuildEntry()
}

// Config describes a log event type in a declarative way.
// To convert to an Entry instance it must be registered.
// The Config/LogType separation enforces mutability rules for registered log event types.
type Config struct {
	Name         string
	Description  string
	ReferenceURL string
	Schema       interface{}
	NewParser    pantherlog.LogParserFactory
}

func (c *Config) Describe() Desc {
	return Desc{
		Name:         c.Name,
		Description:  c.Description,
		ReferenceURL: c.ReferenceURL,
	}
}

// Validate verifies a log type is valid
func (c *Config) Validate() error {
	if c == nil {
		return errors.Errorf("nil log event type c")
	}
	desc := c.Describe()
	if err := desc.Validate(); err != nil {
		return err
	}
	if err := checkLogEntrySchema(desc.Name, c.Schema); err != nil {
		return err
	}
	if c.NewParser == nil {
		return errors.New("nil parser factory")
	}
	return nil
}

// BuildEntry implements EntryBuilder interface
func (c Config) BuildEntry() (Entry, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return newEntry(c.Describe(), c.Schema, c.NewParser), nil
}

type entry struct {
	desc      Desc
	schema    interface{}
	newParser pantherlog.FactoryFunc
}

func newEntry(desc Desc, schema interface{}, fac pantherlog.LogParserFactory) *entry {
	return &entry{
		desc:      desc,
		schema:    schema,
		newParser: fac.NewParser,
	}
}

func (e *entry) Name() string {
	return e.desc.Name
}

func (e *entry) Find(logType string) Entry {
	if e.String() == logType {
		return e
	}
	return nil
}

func (e *entry) Entries() []Entry {
	return []Entry{e}
}

func (e *entry) BuildEntry() (Entry, error) {
	return e, nil
}

func (e *entry) Describe() Desc {
	return e.desc
}

func (e *entry) String() string {
	return e.desc.Name
}

func (e *entry) Schema() interface{} {
	return e.schema
}

// Parser returns a new pantherlog.LogParser
func (e *entry) NewParser(params interface{}) (pantherlog.LogParser, error) {
	return e.newParser(params)
}

func checkLogEntrySchema(logType string, schema interface{}) error {
	if schema == nil {
		return errors.Errorf("nil schema for log type %q", logType)
	}
	data, err := pantherlog.ConfigJSON().Marshal(schema)
	if err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	var fields map[string]interface{}
	if err := pantherlog.ConfigJSON().Unmarshal(data, &fields); err != nil {
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
	cols, err := glueschema.InferColumns(schema)
	if err != nil {
		return
	}
	if len(cols) == 0 {
		err = errors.New("empty columns")
	}
	return
}
