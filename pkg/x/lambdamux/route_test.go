package lambdamux

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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type testAPI struct {
}

func (*testAPI) InvokeFoo(_ context.Context) error {
	return nil
}

func TestStructRoutes(t *testing.T) {
	assert := require.New(t)
	routes, err := routeMethods(DefaultHandlerPrefix, &testAPI{})
	assert.NoError(err)
	assert.Len(routes, 1)
	assert.Nil(routes[0].input)
	assert.Nil(routes[0].output)

	mux := Mux{
		IgnoreDuplicates: true,
	}
	assert.NoError(mux.HandleMethodsPrefix(DefaultHandlerPrefix, &testAPI{}))
	assert.NoError(mux.HandleMethodsPrefix(DefaultHandlerPrefix, &testAPI{}))
	output, err := mux.Invoke(context.Background(), json.RawMessage(`{"Foo":{}}`))
	assert.NoError(err)
	assert.Equal("{}", string(output))
}

func TestSignatures(t *testing.T) {
	assert := require.New(t)
	type Input struct{}
	type Output struct{}
	mustBuildRoute("foo", func() error { return nil })
	mustBuildRoute("bar", func(context.Context) error { return nil })
	mustBuildRoute("baz", func(context.Context) (*Output, error) { return nil, nil })
	mustBuildRoute("foo", func(context.Context) *Output { return nil })
	mustBuildRoute("foo", func(*Input) error { return nil })
	mustBuildRoute("foo", func(*Input) (*Output, error) { return nil, nil })
	mustBuildRoute("foo", func(context.Context, *Input) error { return nil })
	mustBuildRoute("foo", func(context.Context, *Input) (*Output, error) { return nil, nil })
	mustBuildRoute("foo", func() (*Output, error) { return nil, nil })
	for _, method := range []interface{}{
		func(*Input, *Input) error { return nil },
		func(Input) error { return nil },
		func(*Input) {},
		func(Input) (*Output, error) { return nil, nil },
		func(context.Context, Input) error { return nil },
		func(context.Context, string) error { return nil },
		func(context.Context, *Input, *Input) error { return nil },
		func(context.Context, *Input) (Output, error) { return Output{}, nil },
		func(context.Context, *Input) Output { return Output{} },
		func(context.Context, *Input) (string, error) { return "", nil },
		func(context.Context, *Input) (*Output, *Output, error) { return nil, nil, nil },
		func(context.Context, *Input) (*Output, *Output) { return nil, nil },
		func() (Output, error) { return Output{}, nil },
		42,
	} {
		_, err := buildRoute("foo", method)
		assert.Error(err)
	}
}
