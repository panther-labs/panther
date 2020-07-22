package pantherlog

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

func TestValueBuffer_Kinds(t *testing.T) {
	b := ValueBuffer{}
	require.Nil(t, b.Kinds())
	b.WriteValues(1, "")
	require.Empty(t, b.Kinds())
	b.WriteValues(1, "foo", "foo")
	require.Equal(t, []ValueKind{1}, b.Kinds())
	b.WriteValues(2, "foo")
	require.Equal(t, []ValueKind{1, 2}, b.Kinds())
	b.Reset()
	require.Empty(t, b.Kinds())
}

func TestValueBuffer_Get(t *testing.T) {
	b := ValueBuffer{}
	require.Nil(t, b.Get(1))
	b.WriteValues(1, "")
	require.Equal(t, map[ValueKind][]string(nil), b.Inspect())
	require.Nil(t, b.Get(1))
	b.WriteValues(1, "foo")
	require.Equal(t, map[ValueKind][]string{
		1: {"foo"},
	}, b.Inspect())
	require.Equal(t, []string{"foo"}, b.Get(1))
	b.WriteValues(1, "foo", "bar")
	require.Equal(t, []string{"bar", "foo"}, b.Get(1))
	b.WriteValues(2, "")
	require.Equal(t, map[ValueKind][]string{
		1: {"bar", "foo"},
	}, b.Inspect())
	require.True(t, b.Contains(1, "foo"))
	require.True(t, b.Contains(1, "bar"))
	require.False(t, b.Contains(1, "baz"))
	require.False(t, b.Contains(42, "baz"))
	b.Reset()
	require.Equal(t, map[ValueKind][]string{
		1: {},
	}, b.Inspect())
	require.Nil(t, b.Get(1))
}

type sample struct {
	Kind  ValueKind
	Value string
}
type sampleValues []sample

func (samples *sampleValues) WriteValues(kind ValueKind, values ...string) {
	for _, value := range values {
		*samples = append(*samples, sample{
			Kind:  kind,
			Value: value,
		})
	}
}
func TestValueBuffer_WriteValuesTo(t *testing.T) {
	{
		b := ValueBuffer{
			index: map[ValueKind][]string{
				1: {"foo", "bar"},
				2: {"baz"},
			},
		}
		samples := sampleValues{}
		b.WriteValuesTo(&samples)
		expect := sampleValues{
			{1, "foo"},
			{1, "bar"},
			{2, "baz"},
		}
		require.Equal(t, expect, samples)
	}
}

func TestValueBuffer_Clone(t *testing.T) {
	{
		b := ValueBuffer{
			index: map[ValueKind][]string{
				1: {"foo", "bar"},
				2: {"baz"},
			},
		}
		require.Equal(t, b, b.Clone())
	}
	{
		b := ValueBuffer{}
		c := b.Clone()
		require.Equal(t, b, c)
		require.Nil(t, c.index)
	}
	{
		b := ValueBuffer{
			index: map[ValueKind][]string{
				1: {"foo", "bar"},
				2: {"baz"},
				3: {},
			},
		}
		require.Equal(t, ValueBuffer{
			index: map[ValueKind][]string{
				1: {"foo", "bar"},
				2: {"baz"},
			},
		}, b.Clone())
	}
}
