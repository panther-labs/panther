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

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

// Resolver resolves a log type name to it's entry.
// Implementations should use the context argument if they require to make network requests to resolve the entry.
// If an error occurred while trying to resolve the entry it should be returned (nil, err).
// If an entry could not be resolved but no errors occurred the implementations should return `nil, nil`.
type Resolver interface {
	Resolve(ctx context.Context, name string) (Entry, error)
}

var _ Resolver = (*Registry)(nil)

// Resolve implements Resolver for a Registry
func (r *Registry) Resolve(_ context.Context, name string) (Entry, error) {
	if entry := r.Get(name); entry != nil {
		return entry, nil
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

func ResolveTables(ctx context.Context, resolver Resolver, logTypes ...string) ([]*awsglue.GlueTableMetadata, error) {
	tables := make([]*awsglue.GlueTableMetadata, len(logTypes))
	for i, logType := range logTypes {
		entry, err := resolver.Resolve(ctx, logType)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, errors.Errorf("unresolved log type %q", logType)
		}
		tables[i] = entry.GlueTableMeta()
	}
	return tables, nil
}
