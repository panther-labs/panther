package logtypesapi

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
	"strings"
	"sync"
)

// InMemDB is an in-memory implementation of the SchemaDatabase.
// It is useful for tests and for caching results of another implementation.
type InMemDB struct {
	mu      sync.RWMutex
	records map[string]*SchemaRecord
}

var _ SchemaDatabase = (*InMemDB)(nil)

func NewInMemory() *InMemDB {
	return &InMemDB{
		records: map[string]*SchemaRecord{},
	}
}

func (db *InMemDB) GetSchema(_ context.Context, id string) (*SchemaRecord, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result, ok := db.records[strings.ToUpper(id)]
	if !ok {
		return nil, nil
	}
	return result, nil
}

func (db *InMemDB) PutSchema(_ context.Context, name string, r *SchemaRecord) (*SchemaRecord, error) {
	revision := r.Revision
	id := strings.ToUpper(name)
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.records == nil {
		db.records = map[string]*SchemaRecord{}
	}
	current, ok := db.records[id]
	if !ok {
		r.Revision = 1
		db.records[id] = r
		return r, nil
	}
	if current.Revision != revision {
		return nil, NewAPIError("Conflict", "record revision mismatch")
	}
	rec := *r
	rec.Revision++
	db.records[id] = &rec
	return &rec, nil
}

func (db *InMemDB) ScanSchemas(_ context.Context, scan ScanSchemaFunc) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, r := range db.records {
		if !scan(r) {
			return nil
		}
	}
	return nil
}
