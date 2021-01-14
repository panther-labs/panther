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
	"sync"
	"time"

	"github.com/panther-labs/panther/pkg/stringset"
)

// InMemDB is an in-memory implementation of the LogTypesDatabase.
// It is useful for tests and for caching results of another implementation.
type InMemDB struct {
	mu      sync.RWMutex
	deleted []string
	records map[inMemKey]*CustomLogRecord
}

type inMemKey struct {
	LogType  string
	Revision int64
}

var _ LogTypesDatabase = (*InMemDB)(nil)

func NewInMemory() *InMemDB {
	return &InMemDB{
		records: map[inMemKey]*CustomLogRecord{},
	}
}

func (db *InMemDB) IndexLogTypes(_ context.Context) ([]string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	logtypes := make([]string, 0, len(db.records))
	for key := range db.records {
		logtypes = appendDistinct(logtypes, key.LogType)
	}
	return logtypes, nil
}

func (db *InMemDB) GetCustomLog(_ context.Context, id string, revision int64) (*CustomLogRecord, error) {
	result, ok := db.records[inMemKey{
		LogType:  id,
		Revision: revision,
	}]
	if !ok {
		return nil, nil
	}
	return result, nil
}

func (db *InMemDB) CreateCustomLog(_ context.Context, id string, params *CustomLog) (*CustomLogRecord, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	key := inMemKey{
		LogType:  id,
		Revision: 0,
	}
	if stringset.Contains(db.deleted, id) {
		return nil, NewAPIError(ErrAlreadyExists, "record used to exist but was deleted")
	}
	if _, exists := db.records[key]; exists {
		return nil, NewAPIError(ErrRevisionConflict, "record revision mismatch")
	}
	record := &CustomLogRecord{
		CustomLog: *params,
		LogType:   id,
		Revision:  1,
		UpdatedAt: time.Now(),
	}
	db.records[key] = record
	key.Revision = 1
	db.records[key] = record
	return record, nil
}

func (db *InMemDB) UpdateCustomLog(_ context.Context, id string, revision int64, params *CustomLog) (*CustomLogRecord, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	key := inMemKey{
		LogType:  id,
		Revision: 0,
	}
	current, ok := db.records[key]
	if !ok || current.Revision != revision {
		return nil, NewAPIError("Conflict", "record revision mismatch")
	}
	record := &CustomLogRecord{
		CustomLog: *params,
		LogType:   id,
		Revision:  revision + 1,
		UpdatedAt: time.Now(),
	}
	db.records[key] = record
	key.Revision = revision + 1
	db.records[key] = record
	return record, nil
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

func (db *InMemDB) BatchGetCustomLogs(ctx context.Context, ids ...string) ([]*CustomLogRecord, error) {
	var records []*CustomLogRecord
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, id := range ids {
		record, ok := db.records[inMemKey{
			LogType: id,
		}]
		if !ok {
			return nil, NewAPIError(ErrNotFound, fmt.Sprintf(`record %q not found`, id))
		}
		records = append(records, record)
	}
	return records, nil
}

func (db *InMemDB) ListDeletedLogTypes(ctx context.Context) ([]string, error) {
	var out []string
	db.mu.RLock()
	defer db.mu.RUnlock()
	out = append(out, db.deleted...)
	return out, nil
}
