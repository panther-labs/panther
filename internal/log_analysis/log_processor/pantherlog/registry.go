package pantherlog

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
	"sync"

	"github.com/pkg/errors"
)

// Registry is a collection of LogTypes.
// It is safe to use a registry from multiple go routines.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*EventType
}

func NewRegistry(logTypes ...EventType) (*Registry, error) {
	r := &Registry{}
	for _, logType := range logTypes {
		if err := r.Register(logType); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// MustGet gets a registered EventType or panics
func (r *Registry) MustGet(name string) *EventType {
	if logType := r.Get(name); logType != nil {
		return logType
	}
	panic(errors.Errorf("unregistered log type %q", name))
}

// Get returns finds an EventType entry in a registry.
// The returned pointer should be used as a *read-only* share of the EventType.
func (r *Registry) Get(name string) *EventType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// Entries returns copies of EventType entries in a registry.
// If no names are provided all entries are returned.
func (r *Registry) Entries(names ...string) []EventType {
	if names == nil {
		names = r.LogTypes()
	}
	m := make([]EventType, 0, len(names))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, name := range names {
		if entry := r.entries[name]; entry != nil {
			m = append(m, *entry)
		}
	}
	return m
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

// Each calls a function for each EventType entry in the registry
func (r *Registry) Each(fn func(entry *EventType)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entry := range r.entries {
		fn(entry)
	}
}

func (r *Registry) Del(name string) *EventType {
	r.mu.Lock()
	defer r.mu.Unlock()
	if logType, ok := r.entries[name]; ok {
		delete(r.entries, name)
		return logType
	}
	return nil
}

func (r *Registry) Register(entry EventType) error {
	if err := entry.Check(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, duplicate := r.entries[entry.Name]; duplicate {
		return errors.Errorf("duplicate log type entry %q", entry.Name)
	}
	if r.entries == nil {
		r.entries = make(map[string]*EventType)
	}
	r.entries[entry.Name] = &entry
	return nil
}

// Default registry for pantherlog package
var defaultRegistry = &Registry{}

// DefaultRegistry returns the default package wide registry for log types
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Get gets a EventType entry from the package wide registry
func Get(logType string) *EventType {
	return defaultRegistry.Get(logType)
}

// MustGet gets a EventType entry from the package wide registry and panics if `logType` is not registered
func MustGet(logType string) *EventType {
	return defaultRegistry.MustGet(logType)
}

// Register registers log type entries to the package wide registry returning the first error it encounters
func Register(entries ...EventType) error {
	for _, entry := range entries {
		if err := defaultRegistry.Register(entry); err != nil {
			return err
		}
	}
	return nil
}

// Register registers log type entries to the package wide registry panicking if an error occurs
func MustRegister(entries ...EventType) {
	if err := Register(entries...); err != nil {
		panic(err)
	}
}

// Available log types returns the available log type names
func AvailableLogTypes() []string {
	return defaultRegistry.LogTypes()
}
