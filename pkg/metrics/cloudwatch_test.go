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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCounter(t *testing.T) {
	buf := bytes.NewBuffer([]byte{})
	cm := NewCWEmbeddedMetrics(buf)
	// Stubbing the time function
	cm.timeFunc = func() int64 {
		return 1000
	}
	counter := cm.NewCounter("test")
	assert.NoError(t, cm.Sync())
	// Assert nothing is written if there is no data present
	assert.Equal(t, 0, buf.Len())

	counter.Add(10)
	assert.NoError(t, cm.Sync())
	// nolint: lll
	assert.Equal(t, `{"test":10,"_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[[]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`+"\n", buf.String())

	buf.Reset()
	assert.NoError(t, cm.Sync())
	// Assert nothing is written this time - we have already synced
	assert.Equal(t, 0, buf.Len())

	counter.With("dimension2", "dimensionValue2").Add(2)
	assert.NoError(t, cm.Sync())
	// nolint: lll
	assert.Equal(t, `{"test":2,"dimension2":"dimensionValue2","_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[["dimension2"]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`+"\n", buf.String())
}
