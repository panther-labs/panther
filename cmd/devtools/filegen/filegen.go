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
)

const (
	DateFormat  = "2006-01-02T15"
	defaultRows = 1000
)

type Generator interface {
	WithRows(nrows int) // set rows
	LogType() string
	Filename(hour time.Time) string
	NewFile(hour time.Time) *File
}

type File struct {
	name              string
	Data              *bytes.Reader
	writer            *gzip.Writer
	buffer            bytes.Buffer
	uncompressedBytes uint64
}

func NewFile(gen Generator, hour time.Time) *File {
	f := &File{
		name: gen.LogType() + "/" + hour.Format(DateFormat) + "/" + gen.Filename(hour) + ".gz",
	}
	f.writer, _ = gzip.NewWriterLevel(&f.buffer, gzip.BestSpeed)
	return f
}

func (f *File) Name() string {
	return f.name
}

func (f *File) Close() {
	_ = f.writer.Close()
	f.Data = bytes.NewReader(f.buffer.Bytes())
}

func (f *File) Write(b []byte) (int, error) {
	f.uncompressedBytes += uint64(len(b))
	return f.writer.Write(b)
}

func (f *File) TotalUncompressedBytes() uint64 {
	return f.uncompressedBytes
}

func (f *File) TotalBytes() uint64 {
	if f.Data == nil {
		panic("file not closed, cannot call Bytes()")
	}
	return uint64(f.Data.Len())
}
