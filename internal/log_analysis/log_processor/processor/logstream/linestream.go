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
	"errors"
	"io"
	"io/ioutil"

	"go.uber.org/multierr"
)

const (
	MinBufferSize     = 512
	DefaultBufferSize = 65536
)

type Stream interface {
	Next() ([]byte, error)
	Close() error
}

type LineStream struct {
	r       *bufio.Reader
	err     error
	rc      io.ReadCloser
	scratch []byte
}

func NewLineStream(r io.Reader, size int) *LineStream {
	if size <= 0 {
		size = DefaultBufferSize
	} else if size < MinBufferSize {
		size = MinBufferSize
	}

	return &LineStream{
		r:  bufio.NewReaderSize(r, size),
		rc: asReadCloser(r),
	}
}
func asReadCloser(r io.Reader) io.ReadCloser {
	if rc, ok := r.(io.ReadCloser); ok {
		return rc
	}
	return ioutil.NopCloser(r)
}

func (s *LineStream) Next() ([]byte, error) {
	if s.rc == nil {
		return nil, io.EOF
	}
	line, isPrefix, err := s.r.ReadLine()
	if err != nil {
		return s.readError(line, err)
	}
	if !isPrefix {
		return line, nil
	}
	// line is longer than bufio.Reader size, reuse scratch
	s.scratch = append(s.scratch[:0], line...)
	for isPrefix {
		line, isPrefix, err = s.r.ReadLine()
		s.scratch = append(s.scratch, line...)
		if err != nil {
			return s.readError(s.scratch, err)
		}
	}
	return s.scratch, nil
}

func (s *LineStream) readError(p []byte, err error) ([]byte, error) {
	if err != io.EOF {
		s.err = err
	}
	closeErr := s.Close()
	// Store read error along with close error
	if closeErr != nil && closeErr != ErrClosed {
		s.err = multierr.Append(s.err, closeErr)
	}
	return p, err
}

var ErrClosed = errors.New("stream closed")

func (s *LineStream) Close() error {
	var rc io.ReadCloser
	rc, s.rc = s.rc, nil
	if rc == nil {
		return s.err
	}
	if err := rc.Close(); err != nil {
		s.err = err
		return err
	}
	s.err = ErrClosed
	return nil
}
