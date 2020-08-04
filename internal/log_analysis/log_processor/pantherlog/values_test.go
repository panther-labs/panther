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
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValueBuffer_Kinds(t *testing.T) {
	b := ValueBuffer{}
	require.Nil(t, b.Fields())
	b.WriteValues(1, "")
	require.Empty(t, b.Fields())
	b.WriteValues(1, "foo", "foo")
	require.Equal(t, []FieldID{1}, b.Fields())
	b.WriteValues(2, "foo")
	require.Equal(t, []FieldID{1, 2}, b.Fields())
	b.Reset()
	require.Empty(t, b.Fields())
}

func TestValueBuffer_Get(t *testing.T) {
	b := ValueBuffer{}
	require.Nil(t, b.Get(1))
	b.WriteValues(1, "")
	require.Equal(t, map[FieldID][]string(nil), b.Inspect())
	require.Nil(t, b.Get(1))
	b.WriteValues(1, "foo")
	require.Equal(t, map[FieldID][]string{
		1: {"foo"},
	}, b.Inspect())
	require.Equal(t, []string{"foo"}, b.Get(1))
	b.WriteValues(1, "foo", "bar")
	require.Equal(t, []string{"bar", "foo"}, b.Get(1))
	b.WriteValues(2, "")
	require.Equal(t, map[FieldID][]string{
		1: {"bar", "foo"},
	}, b.Inspect())
	require.True(t, b.Contains(1, "foo"))
	require.True(t, b.Contains(1, "bar"))
	require.False(t, b.Contains(1, "baz"))
	require.False(t, b.Contains(42, "baz"))
	b.Reset()
	require.Equal(t, map[FieldID][]string{
		1: {},
	}, b.Inspect())
	require.Nil(t, b.Get(1))
}

type sample struct {
	Kind  FieldID
	Value string
}
type sampleValues []sample

func (samples *sampleValues) WriteValues(kind FieldID, values ...string) {
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
			index: map[FieldID][]string{
				1: {"foo", "bar"},
				2: {"baz"},
			},
		}
		samples := sampleValues{}
		b.WriteValuesTo(&samples)
		sort.Slice(samples, func(i, j int) bool {
			a := &samples[i]
			b := &samples[j]
			if a.Kind == b.Kind {
				return a.Value < b.Value
			}
			return a.Kind < b.Kind
		})

		expect := sampleValues{
			{1, "bar"},
			{1, "foo"},
			{2, "baz"},
		}
		require.Equal(t, expect, samples)
	}
}
