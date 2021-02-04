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
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// Resolver resolves a log type name to it's entry.
// Implementations should use the context argument if they require to make network requests to resolve the entry.
// If an error occurred while trying to resolve the entry it should be returned (nil, err).
// If an entry could not be resolved but no errors occurred the implementations should return `nil, nil`.
type Resolver interface {
	Resolve(ctx context.Context, name string) (Entry, error)
}

func ParserResolver(r Resolver) pantherlog.ParserResolver {
	return &parserResolver{
		r: r,
	}
}

type parserResolver struct {
	r Resolver
}

func (p *parserResolver) ResolveParser(ctx context.Context, name string) (pantherlog.LogParser, error) {
	entry, err := p.r.Resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		return entry.NewParser(nil)
	}
	return nil, nil
}

// LocalResolver returns a log type resolver that looks up entries locally
func LocalResolver(finders ...Finder) Resolver {
	return &localResolver{
		finders: finders,
	}
}

type localResolver struct {
	finders []Finder
}

func (r *localResolver) Resolve(_ context.Context, logType string) (Entry, error) {
	for _, finder := range r.finders {
		if entry := finder.Find(logType); entry != nil {
			return entry, nil
		}
	}
	return nil, nil
}

// ChainResolvers tries multiple resolvers in order returning the first resolved entry
func ChainResolvers(resolvers ...Resolver) Resolver {
	return chainResolver(resolvers)
}

type chainResolver []Resolver

// Resolve implements Resolver returning the first resolved entry
func (c chainResolver) Resolve(ctx context.Context, name string) (Entry, error) {
	for _, r := range c {
		entry, err := r.Resolve(ctx, name)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			return entry, nil
		}
	}
	return nil, nil
}

// NewCachedResolver creates a new resolver that caches entries for maxAge duration.
func NewCachedResolver(maxAge time.Duration, r Resolver) *CachedResolver {
	return &CachedResolver{
		maxAge:   maxAge,
		upstream: r,
		entries:  make(map[string]*cachedEntry),
	}
}

type CachedResolver struct {
	maxAge   time.Duration
	upstream Resolver
	group    singleflight.Group
	mu       sync.RWMutex
	entries  map[string]*cachedEntry
}

type cachedEntry struct {
	Entry
	resolvedAt time.Time
}

func (e *cachedEntry) IsValid(maxAge time.Duration) bool {
	return e != nil && time.Since(e.resolvedAt) < maxAge
}

func (c *CachedResolver) Forget(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, name)
}

func (c *CachedResolver) Resolve(ctx context.Context, name string) (Entry, error) {
	if e := c.find(name); e.IsValid(c.maxAge) {
		return e.Entry, nil
	}
	reply, err, _ := c.group.Do(name, func() (interface{}, error) {
		entry, err := c.upstream.Resolve(ctx, name)
		if err != nil {
			return nil, err
		}
		c.set(name, entry)
		return entry, nil
	})
	if err != nil {
		return nil, err
	}
	if entry, ok := reply.(Entry); ok {
		return entry, nil
	}
	return nil, nil
}

func (c *CachedResolver) find(name string) *cachedEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[name]
}

func (c *CachedResolver) set(name string, e Entry) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*cachedEntry)
	}
	c.entries[name] = &cachedEntry{
		Entry:      e,
		resolvedAt: now,
	}
}

type ResolverFunc func(ctx context.Context, name string) (Entry, error)

var _ Resolver = (ResolverFunc)(nil)

func (f ResolverFunc) Resolve(ctx context.Context, name string) (Entry, error) {
	return f(ctx, name)
}
