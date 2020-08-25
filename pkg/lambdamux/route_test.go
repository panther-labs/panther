package lambdamux

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

type testAPI struct {
}

func (*testAPI) HandleFooWithContext(ctx context.Context) error {
	return nil
}

func TestStructRoutes(t *testing.T) {
	assert := require.New(t)
	routes, err := StructRoutes(DefaultHandlerPrefix, &testAPI{})
	assert.NoError(err)
	assert.Len(routes, 1)
	assert.Nil(routes[0].input)
	assert.Nil(routes[0].output)
	assert.True(routes[0].withError)
	assert.True(routes[0].withContext)
	assert.Equal(1, routes[0].method.Type().NumIn())
}
