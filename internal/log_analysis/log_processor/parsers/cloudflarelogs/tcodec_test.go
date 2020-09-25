package cloudflarelogs

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
	"fmt"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestTimeDecoder(t *testing.T) {
	testTime := time.Date(2020, 1, 23, 12, 56, 32, 12345676, time.UTC)
	type testCase struct {
		Name      string
		InputJSON string
		Actual    time.Time
		WantError bool
	}
	for _, tc := range []testCase{
		{
			"RFC3339",
			fmt.Sprintf(`"%s"`, testTime.Format(time.RFC3339Nano)),
			testTime,
			false,
		},
		{
			"Unix Nano",
			fmt.Sprintf(`%d`, testTime.UnixNano()),
			testTime,
			false,
		},
		{
			"Unix Seconds",
			fmt.Sprintf(`%d`, testTime.Unix()),
			testTime.Truncate(time.Second),
			false,
		},
		{
			"Invalid layout",
			fmt.Sprintf(`"%s"`, testTime.Format(time.RFC1123)),
			time.Time{},
			true,
		},
		{
			"Invalid JSON",
			`{}`,
			time.Time{},
			true,
		},
		{
			"Null JSON",
			`null`,
			time.Time{},
			true,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			d := timeDecoder{}
			iter := jsoniter.NewIterator(jsoniter.ConfigDefault)
			iter.ResetBytes([]byte(tc.InputJSON))
			tm := d.DecodeTime(iter)
			assert := require.New(t)
			if tc.WantError {
				assert.Error(iter.Error)
				assert.Zero(tm)
			} else {
				assert.NoError(iter.Error)
				assert.Equal(tc.Actual.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
			}
		})
	}
}
