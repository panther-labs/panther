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
	"encoding/csv"
	"io"
)

type StreamingCSVReader struct {
	CVSReader *csv.Reader
	logLine   string
}

func NewStreamingCSVReader() (scr *StreamingCSVReader) {
	scr = &StreamingCSVReader{}
	reader := csv.NewReader(scr)
	reader.FieldsPerRecord = -1 // variable fields allowed
	reader.ReuseRecord = true   // for performance
	scr.CVSReader = reader
	return scr
}

// for io.Reader signature
func (scr *StreamingCSVReader) Read(b []byte) (n int, err error) {
	n = copy(b, scr.logLine)
	if n < len(scr.logLine) { // partial copy
		scr.logLine = scr.logLine[n:] // the rest for next call
		return n, nil
	}
	// Full copy has been performed
	scr.logLine = ""
	return n, io.EOF
}

func (scr *StreamingCSVReader) Parse(log string) ([]string, error) {
	scr.logLine = log
	return scr.CVSReader.Read()
}
