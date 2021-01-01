package filegen

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
	"compress/gzip"
	"time"

	"github.com/google/uuid"
)

const (
	DateFormat  = "2006-01-02T15"
	defaultRows = 1000
)

type Generator interface {
	WithRows(nrows int) // set rows
	NewFile(hour time.Time) *File
}

type File struct {
	Name string
	Data *bytes.Reader
	writer *gzip.Writer
	buffer bytes.Buffer
}

func NewFile(logType string, hour time.Time) *File {
	f :=  &File{
		Name: logType + "/" + hour.Format(DateFormat) + "/" + uuid.New().String() + ".gz",
	}
	f.writer = gzip.NewWriter(&f.buffer)
	return f
}

func (f *File) Close() {
	f.writer.Close()
	f.Data = bytes.NewReader(f.buffer.Bytes())
}

func (f *File) Write(b []byte) (int, error) {
	return f.writer.Write(b)
}