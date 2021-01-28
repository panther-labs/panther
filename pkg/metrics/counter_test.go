package metrics

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
	"strings"
	"testing"
)

func TestWith(t *testing.T) {
	var a DimensionValues
	b := a.With("a", "1")
	c := a.With("b", "2", "c", "3")

	if want, have := "", strings.Join(a, ""); want != have {
		t.Errorf("With appears to mutate the original LabelValues: want %q, have %q", want, have)
	}
	if want, have := "a1", strings.Join(b, ""); want != have {
		t.Errorf("With does not appear to return the right thing: want %q, have %q", want, have)
	}
	if want, have := "b2c3", strings.Join(c, ""); want != have {
		t.Errorf("With does not appear to return the right thing: want %q, have %q", want, have)
	}
}

func TestSpaceWalkAbort(t *testing.T) {
	s := NewSpace()
	s.Observe("a", DimensionValues{"a", "b"}, 1)
	s.Observe("a", DimensionValues{"c", "d"}, 2)
	s.Observe("a", DimensionValues{"e", "f"}, 4)
	s.Observe("a", DimensionValues{"g", "h"}, 8)
	s.Observe("b", DimensionValues{"a", "b"}, 16)
	s.Observe("b", DimensionValues{"c", "d"}, 32)
	s.Observe("b", DimensionValues{"e", "f"}, 64)
	s.Observe("b", DimensionValues{"g", "h"}, 128)

	var count int
	s.Walk(func(name string, lvs DimensionValues, obs []float64) bool {
		count++
		return false
	})
	if want, have := 1, count; want != have {
		t.Errorf("want %d, have %d", want, have)
	}
}

func TestSpaceWalkSums(t *testing.T) {
	s := NewSpace()
	s.Observe("metric_one", DimensionValues{}, 1)
	s.Observe("metric_one", DimensionValues{}, 2)
	s.Observe("metric_one", DimensionValues{"a", "1", "b", "2"}, 4)
	s.Observe("metric_one", DimensionValues{"a", "1", "b", "2"}, 8)
	s.Observe("metric_one", DimensionValues{}, 16)
	s.Observe("metric_one", DimensionValues{"a", "1", "b", "3"}, 32)
	s.Observe("metric_two", DimensionValues{}, 64)
	s.Observe("metric_two", DimensionValues{}, 128)
	s.Observe("metric_two", DimensionValues{"a", "1", "b", "2"}, 256)

	have := map[string]float64{}
	s.Walk(func(name string, lvs DimensionValues, obs []float64) bool {
		have[name+" ["+strings.Join(lvs, "")+"]"] += sum(obs)
		return true
	})

	want := map[string]float64{
		"metric_one []":     1 + 2 + 16,
		"metric_one [a1b2]": 4 + 8,
		"metric_one [a1b3]": 32,
		"metric_two []":     64 + 128,
		"metric_two [a1b2]": 256,
	}
	for keystr, wantsum := range want {
		if havesum := have[keystr]; wantsum != havesum {
			t.Errorf("%q: want %.1f, have %.1f", keystr, wantsum, havesum)
		}
		delete(want, keystr)
		delete(have, keystr)
	}
	for keystr, havesum := range have {
		t.Errorf("%q: unexpected observations recorded: %.1f", keystr, havesum)
	}
}

func TestSpaceWalkSkipsEmptyDimensions(t *testing.T) {
	s := NewSpace()
	s.Observe("foo", DimensionValues{"bar", "1", "baz", "2"}, 123)

	var count int
	s.Walk(func(name string, lvs DimensionValues, obs []float64) bool {
		count++
		return true
	})
	if want, have := 1, count; want != have {
		t.Errorf("want %d, have %d", want, have)
	}
}
