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
	"fmt"
	"strings"
	"sync"
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

	t.Run("no metrics", func(t *testing.T) {
		buf.Reset()
		cm.NewCounter("test", UnitBytes)
		assert.NoError(t, cm.Sync())
		// Assert nothing is written if there is no data present
		assert.Equal(t, 0, buf.Len())
	})

	t.Run("counter without dimensions", func(t *testing.T) {
		buf.Reset()
		counter := cm.NewCounter("test", UnitBytes)
		counter.Add(10)
		assert.NoError(t, cm.Sync())
		// nolint: lll
		assert.Equal(t, `{"test":10,"_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[[]],"Metrics":[{"Name":"test","Unit":"Bytes"}]}],"Timestamp":1000}}`+"\n", buf.String())
	})

	t.Run("clears buffer after syncing", func(t *testing.T) {
		buf.Reset()
		counter := cm.NewCounter("test", UnitBytes)
		counter.Add(10)
		assert.NoError(t, cm.Sync())
		assert.True(t, buf.Len() > 0)

		buf.Reset()
		// This sync shouldn't write anything, we already synced above
		assert.NoError(t, cm.Sync())
		assert.Equal(t, 0, buf.Len())
	})

	t.Run("multiple dimensions", func(t *testing.T) {
		buf.Reset()
		counter := cm.NewCounter("test", UnitCount)

		counter.With("dimension1", "value1").Add(1)
		counter.With("dimension2", "value2").Add(1)
		assert.NoError(t, cm.Sync())
		// nolint: lll

		// nolint: lll
		expected := []string{
			`{"test":1,"dimension1":"value1","_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[["dimension1"]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`,
			`{"test":1,"dimension2":"value2","_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[["dimension2"]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`,
		}

		// The output will be like `<json>\n<json>\n`. The `strings.Split` will generate a slice with 3 strings
		// one of them will be the empty string
		assert.ElementsMatch(t, append(expected, ""), strings.Split(buf.String(), "\n"))
	})

	t.Run("multiple counters for same dimensions", func(t *testing.T) {
		buf.Reset()
		counter := cm.NewCounter("test", UnitCount)

		counter.With("dimension1", "value1", "dimension2", "value2").Add(1)
		counter.With("dimension1", "value1", "dimension2", "value2").Add(1)
		assert.NoError(t, cm.Sync())
		// nolint: lll
		assert.Equal(t, `{"test":2,"dimension1":"value1","dimension2":"value2","_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[["dimension1","dimension2"]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`+"\n", buf.String())
	})

	t.Run("multiple dimension values", func(t *testing.T) {
		buf.Reset()
		counter := cm.NewCounter("test", UnitCount)

		counter.With("dimension", "value1").Add(1)
		counter.With("dimension", "value2").Add(2)
		assert.NoError(t, cm.Sync())

		// nolint: lll
		expected := []string{
			`{"test":1,"dimension":"value1","_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[["dimension"]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`,
			`{"test":2,"dimension":"value2","_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[["dimension"]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`,
		}

		// The output will be like `<json>\n<json>\n`. The `strings.Split` will generate a slice with 3 strings
		// one of them will be the empty string
		assert.ElementsMatch(t, append(expected, ""), strings.Split(buf.String(), "\n"))
	})

	t.Run("concurrent counter creation", func(t *testing.T) {
		buf.Reset()

		const parallelInvocations = 100
		var wg sync.WaitGroup
		for i := 0; i < parallelInvocations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				counter := cm.NewCounter("test", UnitCount)
				counter.With("dimension", "value1").Add(1)
			}()
		}

		wg.Wait()

		assert.NoError(t, cm.Sync())
		// nolint: lll
		assert.Equal(t, fmt.Sprintf(`{"test":%d,"dimension":"value1","_aws":{"CloudWatchMetrics":[{"Namespace":"Panther","Dimensions":[["dimension"]],"Metrics":[{"Name":"test","Unit":"Count"}]}],"Timestamp":1000}}`, parallelInvocations)+"\n", buf.String())
	})
}
