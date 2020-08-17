package util

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
	"crypto/md5" // nolint: gosec
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileDiffs(t *testing.T) {
	hello := md5.Sum([]byte("hello"))     // nolint: gosec
	panther := md5.Sum([]byte("panther")) // nolint: gosec
	world := md5.Sum([]byte("world"))     // nolint: gosec

	type set = map[string][16]byte

	// no diffs
	assert.Nil(t, FileDiffs(nil, nil))
	assert.Nil(t, FileDiffs(
		set{"A": hello, "B": panther, "C": world},
		set{"C": world, "B": panther, "A": hello}))

	// only modifications
	assert.Equal(t, []string{"~ B"}, FileDiffs(
		set{"A": hello, "B": panther, "C": world},
		set{"A": hello, "B": world, "C": world}))

	// only additions
	result := FileDiffs(nil, set{"A": hello, "B": panther, "C": world})
	sort.Strings(result)
	assert.Equal(t, []string{"+ A", "+ B", "+ C"}, result)

	// only deletions
	result = FileDiffs(set{"A": hello, "B": panther, "C": world}, set{"A": hello})
	sort.Strings(result)
	assert.Equal(t, []string{"- B", "- C"}, result)

	// all types
	result = FileDiffs(
		set{"A": hello, "B": panther, "C": world, "D": hello},
		set{"A": panther, "C": world, "D": world, "E": hello},
	)
	sort.Strings(result)
	assert.Equal(t, []string{"+ E", "- B", "~ A", "~ D"}, result)
}
