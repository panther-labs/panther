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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestCachedResolver(t *testing.T) {
	entry := MustBuild(ConfigJSON{
		Name:         "Foo",
		Description:  "Bar",
		ReferenceURL: "-",
		NewEvent: func() interface{} {
			return &struct {
				Foo string
			}{}
		},
	})

	var numCalls int64
	upstream := ResolverFunc(func(ctx context.Context, name string) (Entry, error) {
		atomic.AddInt64(&numCalls, 1)
		// Simulate some latency so that singleflight always kicks in
		time.Sleep(5 * time.Millisecond)
		if name == "Foo" {
			return entry, nil
		}
		return nil, nil
	})

	const maxAge = 200 * time.Millisecond
	r := NewCachedResolver(maxAge, upstream)
	grp, ctx := errgroup.WithContext(context.Background())
	assert := require.New(t)
	for i := 0; i < 100; i++ {
		grp.Go(func() error {
			e, err := r.Resolve(ctx, "Foo")
			if err != nil {
				return err
			}
			assert.Equal(e, entry)
			return nil
		})
	}
	assert.NoError(grp.Wait())

	time.Sleep(maxAge)

	e, err := r.Resolve(ctx, "Foo")
	assert.NoError(err)
	assert.Equal(e, entry)
	assert.Equal(int64(2), numCalls)
}
