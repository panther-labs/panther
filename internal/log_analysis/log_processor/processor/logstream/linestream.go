package logstream

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
	"bufio"
	goerrors "errors"
	"io"
	"unicode/utf8"
)

const (
	MinBufferSize     = 512
	DefaultBufferSize = 65536
)

// Stream is the common interface for reading log entries
type Stream interface {
	// Next will read the next log entry.
	// If it returns `nil` no more log entries are available in the stream.
	// The slice returned is stable until the next call to `Next()`
	Next() []byte
	// Err returns the first non-EOF error that was encountered by the Stream.
	Err() error
}

type LineStream struct {
	r        *bufio.Reader
	err      error
	numLines int64
	scratch  []byte
}

func NewLineStream(r io.Reader, size int) *LineStream {
	if size <= 0 {
		size = DefaultBufferSize
	} else if size < MinBufferSize {
		size = MinBufferSize
	}

	return &LineStream{
		r: bufio.NewReaderSize(r, size),
	}
}

// Err returns the first non-EOF error that was encountered by the Scanner.
func (s *LineStream) Err() error {
	if s.err == io.EOF {
		return nil
	}
	return s.err
}

// Next reads the next line from the log.
func (s *LineStream) Next() []byte {
	if s.err != nil {
		return nil
	}
	line, err := s.readLine()
	if line != nil {
		s.numLines++
	}
	if err != nil {
		s.err = err
	}
	return line
}

var ErrInvalidUTF8 = goerrors.New("invalid UTF8 encoding")

func (s *LineStream) readLine() ([]byte, error) {
	// We use ReadLine instread of ReadBytes("\n") here to avoid unnecessary copying of data.
	// line is a 'live' slice from the bufio.Reader
	// isPrefix is set to true if the line did not fit that read buffer, so that we know this is partial data.
	// err is any read error that occurred.
	// NOTE: ReadLine either returns a non-nil line or it returns an error, never both.
	// Another reason for using ReadLine is that with it, we can detect UTF8 on the first line chunk.
	// If we were using ReadBytes("\n"), and the file was a non-UTF8 blob, we might end up reading the whole file seatching for "\n".
	line, isPrefix, err := s.r.ReadLine()
	if err != nil {
		return nil, err
	}
	// Check for valid UTF8 stream on first read.
	// We want to be doing this here, before handling isPrefix.
	// This allows us to avoid reading a whole non-UTF8 blob searching for "\n"
	// NOTE: if we encounter 'weird' log files using UTF16 and/or BOM headers, we need to update this detection
	if s.numLines == 0 {
		if !isValidUTF8(line, isPrefix) {
			return nil, ErrInvalidUTF8
		}
	}
	if !isPrefix {
		// Line was small enough to fit the bufio.Reader buffer size.
		return line, nil
	}
	// Uh-oh, line is longer than bufio.Reader size.
	// The bytes in 'line' are valid until the next call to ReadLine.
	// We will have to copy the bytes somewhere.
	// Reuse our scratch buffer so that we don't allocate on every long line.
	s.scratch = append(s.scratch[:0], line...)
	// Keep reading chunks, copying them to scratch until we find the end of the line.
	for isPrefix {
		// Read the next chunk
		line, isPrefix, err = s.r.ReadLine()
		// Remember: ReadLine either returns a non-nil line or it returns an error, never both.
		if err != nil {
			break
		}
		s.scratch = append(s.scratch, line...)
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	return s.scratch, err
}

func isValidUTF8(p []byte, partial bool) bool {
	totalSize := len(p)
	validSize := 0
	for len(p) > 0 {
		r, n := utf8.DecodeRune(p)
		if r == utf8.RuneError {
			break
		}
		p = p[n:]
		validSize += n
	}
	if partial {
		diff := totalSize - validSize
		// Ensure that the invalid bytes remaining are a partially read UTF8 rune
		return diff < utf8.UTFMax
	}
	return validSize == totalSize
}
