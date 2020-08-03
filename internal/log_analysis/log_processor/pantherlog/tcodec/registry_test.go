package tcodec

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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultRegistry(t *testing.T) {
	require.Equal(t, defaultRegistry, DefaultRegistry())
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)
	require.Empty(t, r.codecs)
}

func TestRegistry_Extend(t *testing.T) {
	r := Registry{}
	r.Extend(DefaultRegistry())
	require.Equal(t, defaultRegistry.codecs, r.codecs)
	b := NewRegistry()
	codec := LayoutCodec(`2006`)
	require.NoError(t, b.Register("foo", codec))
	require.Panics(t, func() {
		b.MustRegister("foo", codec)
	})
	r.Extend(&r, DefaultRegistry(), b, nil)
	require.NotNil(t, r.Lookup("foo"))
	require.Equal(t, codec, r.Lookup("foo"))
}
func TestRegistry_Register(t *testing.T) {
	r := Registry{}
	codec := LayoutCodec(`2006`)
	require.NoError(t, r.Register("foo", codec))
	require.Error(t, r.Register("foo", codec))
	require.Error(t, r.Register("", codec))
	require.Error(t, r.Register("bar", nil))
	require.Panics(t, func() {
		r.MustRegister("foo", codec)
	})
	require.Panics(t, func() {
		r.MustRegister("", codec)
	})
	require.Equal(t, codec, r.Lookup("foo"))
	require.Nil(t, r.Lookup("bar"))
}
