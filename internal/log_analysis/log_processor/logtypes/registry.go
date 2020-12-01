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
	"context"
	"sync"

	"github.com/pkg/errors"
)

// Registry is a collection of log type entries.
// It is safe to use a registry from multiple goroutines.
type Registry struct {
	name  string
	mu    sync.RWMutex
	group group
}

// Find returns finds an LogTypeConfig entry in a registry.
// The returned pointer should be used as a *read-only* share of the LogTypeConfig.
func (r *Registry) Find(logType string) Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.group.Find(logType)
}

// Entries returns log type entries in a registry.
func (r *Registry) Entries() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.group.Entries()
}

func (r *Registry) Name() string {
	return r.name
}

// Resolve implements Resolver for a Registry
func (r *Registry) Resolve(_ context.Context, name string) (Entry, error) {
	return r.Find(name), nil
}

var _ Group = (*Registry)(nil)

func MustBuildRegistry(name string, groups ...Group) *Registry {
	r, err := BuildRegistry(name, groups...)
	if err != nil {
		panic(err)
	}
	return r
}

func BuildRegistry(name string, groups ...Group) (*Registry, error) {
	r := Registry{
		name: name,
	}
	for _, g := range groups {
		if err := r.mergeGroup(g); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

func (r *Registry) mergeGroup(g Group) error {
	for _, entry := range g.Entries() {
		name := entry.String()
		if _, duplicate := r.group.entries[name]; duplicate {
			return errors.Errorf(`duplicate entry %q`, name)
		}
		if r.group.entries == nil {
			r.group.entries = map[string]Entry{}
		}
		r.group.entries[name] = entry
	}
	return nil
}

// LogTypes returns all available log types in a registry
func (r *Registry) LogTypes() (logTypes []string) {
	// Avoid allocation under lock
	const minLogTypesSize = 32
	logTypes = make([]string, 0, minLogTypesSize)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for logType := range r.group.entries {
		logTypes = append(logTypes, logType)
	}
	return
}

// Del deletes an entry from the registry
func (r *Registry) Del(logType string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.group.entries[logType]; ok {
		delete(r.group.entries, logType)
		return true
	}
	return false
}

// Register registers log type entries or fails if there are name conflicts
func (r *Registry) Register(g Group) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mergeGroup(g)
}

// MustRegister registers log type entries or panics if there are name conflicts
func (r *Registry) MustRegister(g Group) {
	if err := r.Register(g); err != nil {
		panic(err)
	}
}
