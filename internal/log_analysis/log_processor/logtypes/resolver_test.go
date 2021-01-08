package logtypes

import (
	"context"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"sync/atomic"
	"testing"
	"time"
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
