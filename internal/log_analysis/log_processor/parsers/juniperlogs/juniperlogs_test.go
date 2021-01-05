package juniperlogs

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
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimestampParser(t *testing.T) {
	{
		p := timestampParser{
			Now: time.Date(2003, 1, 1, 0, 0, 1, 0, time.UTC),
		}
		tm, err := p.ParseTimestamp("Jan 01 00:00:00")
		assert.NoError(t, err)
		assert.Equal(t, tm, time.Date(2003, 1, 1, 0, 0, 0, 0, time.UTC))
	}
	{
		p := timestampParser{
			Now: time.Date(2003, 1, 1, 0, 0, 1, 0, time.UTC),
		}
		tm, err := p.ParseTimestamp("Jan 1 00:00:00")
		assert.NoError(t, err)
		assert.Equal(t, tm, time.Date(2003, 1, 1, 0, 0, 0, 0, time.UTC))
	}
	{
		p := timestampParser{
			Now: time.Date(2003, 1, 1, 0, 0, 1, 0, time.UTC),
		}
		tm, err := p.ParseTimestamp("Dec 31 23:59:59")
		assert.NoError(t, err)
		assert.Equal(t, tm, time.Date(2002, 12, 31, 23, 59, 59, 0, time.UTC))
	}
	{
		p := timestampParser{
			Now: time.Date(2003, 1, 1, 0, 0, 1, 0, time.UTC),
		}
		_, err := p.ParseTimestamp("Dec 32 23:59:59")
		assert.Error(t, err)
	}
}

func expectedTestDate(t time.Time) time.Time {
	now := time.Now().UTC()
	if now.Month() == time.January && t.Month() > now.Month() {
		return time.Date(now.Year()-1, t.Month(), t.Day(), t.Hour(), t.Minute(),
			t.Second(), t.Nanosecond(), t.Location())
	}
	return t
}
