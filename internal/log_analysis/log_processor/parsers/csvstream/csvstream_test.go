package csvstream

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStreamingCSVReader(t *testing.T) {
	// basic reading
	reader := NewStreamingCSVReader()
	line := "a,b,c,d"
	expectedLine := strings.Split(line, ",")
	lines := []string{
		line,
		line,
		line,
	}
	for _, l := range lines {
		record, err := reader.Parse(l)
		require.NoError(t, err)
		assert.Equal(t, expectedLine, record)
	}
}

func TestNewStreamingCSVReaderLongLines(t *testing.T) {
	// test when lines are longer than the internal 4096 buffer in the Go csv reader
	reader := NewStreamingCSVReader()
	var lineElements []string
	for len(lineElements) < 10000 {
		lineElements = append(lineElements, "a")
	}
	line := strings.Join(lineElements, ",")
	expectedLine := strings.Split(line, ",")
	lines := []string{
		line,
		line,
		line,
	}
	for _, l := range lines {
		record, err := reader.Parse(l)
		require.NoError(t, err)
		assert.Equal(t, expectedLine, record)
	}
}

func TestNewStreamingCSVReaderReadingEmptyString(t *testing.T) {
	reader := NewStreamingCSVReader()
	reader.logLine = ""
	buffer := make([]byte, 100)
	result, err := reader.Read(buffer)
	assert.Equal(t, 0, result)
	assert.EqualError(t, io.EOF, err.Error())
}
