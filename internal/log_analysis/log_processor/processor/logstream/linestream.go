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
	if err := s.err; err != nil {
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
	line, isPrefix, err := s.r.ReadLine()
	// NOTE: ReadLine either returns a non-nil line or it returns an error, never both.
	if err != nil {
		return nil, err
	}
	if s.numLines == 0 {
		// Check for valid UTF8 stream on first read.
		if !isValidUTF8(line, isPrefix) {
			return nil, ErrInvalidUTF8
		}
	}
	if !isPrefix {
		return line, nil
	}
	// line is longer than bufio.Reader size, reuse scratch
	s.scratch = append(s.scratch[:0], line...)
	for isPrefix {
		line, isPrefix, err = s.r.ReadLine()
		if err != nil {
			if err == io.EOF {
				return line, nil
			}
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
