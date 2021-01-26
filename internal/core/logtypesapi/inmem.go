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
	"fmt"
	"strings"
	"sync"
	"time"
)

// InMemDB is an in-memory implementation of the SchemaDatabase.
// It is useful for tests and for caching results of another implementation.
type InMemDB struct {
	mu      sync.RWMutex
	deleted []string
	records map[inMemKey]*SchemaRecord
}

type inMemKey struct {
	LogType  string
	Revision int64
}

var _ SchemaDatabase = (*InMemDB)(nil)

func NewInMemory() *InMemDB {
	return &InMemDB{
		records: map[inMemKey]*SchemaRecord{},
	}
}

func (db *InMemDB) GetSchema(_ context.Context, id string, revision int64) (*SchemaRecord, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result, ok := db.records[inMemKey{
		LogType:  strings.ToUpper(id),
		Revision: revision,
	}]
	if !ok {
		return nil, nil
	}
	return result, nil
}

func (db *InMemDB) CreateUserSchema(ctx context.Context, name string, upd SchemaUpdate) (*SchemaRecord, error) {
	now := time.Now()
	db.mu.Lock()
	defer db.mu.Unlock()
	key := inMemKey{
		LogType:  strings.ToUpper(name),
		Revision: 0,
	}
	if _, exists := db.records[key]; exists {
		return nil, NewAPIError(ErrRevisionConflict, "record revision mismatch")
	}
	record := SchemaRecord{
		Name:         name,
		Revision:     1,
		UpdatedAt:    now,
		CreatedAt:    now,
		SchemaUpdate: upd,
	}
	headRecord := record
	db.records[key] = &headRecord
	key.Revision = 1
	revRecord := record
	db.records[key] = &revRecord
	return &record, nil
}

func (db *InMemDB) UpdateUserSchema(ctx context.Context, name string, rev int64, upd SchemaUpdate) (*SchemaRecord, error) {
	revision := rev - 1
	id := strings.ToUpper(name)
	key := inMemKey{
		LogType:  id,
		Revision: 0,
	}
	now := time.Now()
	record := SchemaRecord{
		Name:         name,
		Revision:     rev,
		UpdatedAt:    now,
		CreatedAt:    now,
		SchemaUpdate: upd,
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	current, ok := db.records[key]
	if !ok || current.Revision != revision {
		return nil, NewAPIError("Conflict", "record revision mismatch")
	}
	current.UpdatedAt = now
	current.Revision = rev
	current.SchemaUpdate = upd
	key.Revision = revision + 1
	db.records[key] = &record
	return &record, nil
}

func (db *InMemDB) UpdateManagedSchema(ctx context.Context, name string, release string, upd SchemaUpdate) (*SchemaRecord, error) {
	id := strings.ToUpper(name)
	key := inMemKey{
		LogType:  id,
		Revision: 0,
	}
	now := time.Now()
	record := SchemaRecord{
		Name:         name,
		Managed:      true,
		Release:      release,
		UpdatedAt:    now,
		CreatedAt:    now,
		SchemaUpdate: upd,
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	current, ok := db.records[key]
	if !ok {
		db.records[key] = &record
		return &record, nil
	}
	if !ok || !current.Managed || current.Release >= release {
		return nil, NewAPIError("Conflict", "record revision mismatch")
	}
	current.UpdatedAt = now
	current.Release = release
	current.SchemaUpdate = upd
	return &record, nil
}

func (db *InMemDB) ToggleSchema(ctx context.Context, id string, enabled bool) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	record, ok := db.records[inMemKey{
		LogType: strings.ToUpper(id),
	}]
	if ok {
		record.Disabled = !enabled
	}
	return nil
}

func (db *InMemDB) BatchGetSchemas(ctx context.Context, ids ...string) ([]*SchemaRecord, error) {
	var records []*SchemaRecord
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, id := range ids {
		record, ok := db.records[inMemKey{
			LogType: strings.ToUpper(id),
		}]
		if !ok {
			return nil, NewAPIError(ErrNotFound, fmt.Sprintf(`record %q not found`, id))
		}
		records = append(records, record)
	}
	return records, nil
}

func (db *InMemDB) DeleteCustomLog(_ context.Context, id string, revision int64) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	current, ok := db.records[inMemKey{
		LogType: id,
	}]
	if !ok || current.Revision != revision {
		return NewAPIError(ErrRevisionConflict, "record revision mismatch")
	}
	for rev := int64(0); rev < revision; rev++ {
		delete(db.records, inMemKey{
			LogType:  id,
			Revision: rev,
		})
	}
	db.deleted = append(db.deleted, id)
	return nil
}

func (db *InMemDB) ListDeletedLogTypes(ctx context.Context) ([]string, error) {
	var out []string
	db.mu.RLock()
	defer db.mu.RUnlock()
	out = append(out, db.deleted...)
	return out, nil
}

func (db *InMemDB) ScanSchemas(ctx context.Context, scan ScanSchemaFunc) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, r := range db.records {
		if !scan(r) {
			return nil
		}
	}
	return nil
}
