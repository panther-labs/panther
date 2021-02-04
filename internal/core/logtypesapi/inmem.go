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
	"time"

	"golang.org/x/mod/semver"
)

// InMemDB is an in-memory implementation of the SchemaDatabase.
// It is useful for tests and for caching results of another implementation.
type InMemDB struct {
	mu      sync.RWMutex
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

// nolint:lll
func (db *InMemDB) UpdateManagedSchema(_ context.Context, name string, rev int64, release string, upd SchemaUpdate) (*SchemaRecord, error) {
	id := strings.ToUpper(name)
	key := inMemKey{
		LogType:  id,
		Revision: 0,
	}
	now := time.Now()
	currentRevision := rev - 1
	record := SchemaRecord{
		Name:         name,
		Managed:      true,
		Revision:     rev,
		Release:      release,
		UpdatedAt:    now,
		CreatedAt:    now,
		SchemaUpdate: upd,
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.records == nil {
		db.records = map[inMemKey]*SchemaRecord{}
	}
	current, ok := db.records[key]
	if !ok {
		db.records[key] = &record
		return &record, nil
	}
	if !current.Managed || current.Revision != currentRevision || semver.Compare(current.Release, release) != -1 {
		return nil, NewAPIError("Conflict", "record revision mismatch")
	}
	current.UpdatedAt = now
	current.Release = release
	current.Revision = rev
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
