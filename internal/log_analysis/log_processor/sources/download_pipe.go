package sources

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
	"io"

	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Implements a pipe with the writer having the WriteAt interface
type downloadPipe struct {
	downloader *s3manager.Downloader
	reader     *io.PipeReader
	writer     *io.PipeWriter
	buffer     []byte // sized to part size
}

func (dp *downloadPipe) Read(p []byte) (n int, err error) {
	return dp.reader.Read(p)
}

func (dp *downloadPipe) WriteAt(p []byte, offset int64) (n int, err error) {
	// we assume that offset is increasing or staying the same each call!
	// the writer expects to be able to re-write the chuck at the offset if there are errors reading!
	bufferOffset := offset % dp.downloader.PartSize
	n = copy(dp.buffer[bufferOffset:bufferOffset+int64(len(p))], p)
	dp.buffer = dp.buffer[:len(dp.buffer)+n] // extend slice

	// flush?
	if len(dp.buffer) == cap(dp.buffer) {
		err := dp.Flush()
		if err != nil {
			return n, err
		}
	}

	return n, err
}

func (dp *downloadPipe) Flush() error {
	_, err := dp.writer.Write(dp.buffer) // flush
	if err != nil {
		return err
	}
	dp.buffer = dp.buffer[:0] // reset slice
	return nil
}

func (dp *downloadPipe) Close() error {
	err := dp.Flush()
	if err != nil {
		return dp.CloseWithError(err)
	}
	return dp.writer.Close()
}

func (dp *downloadPipe) CloseWithError(err error) error {
	return dp.writer.CloseWithError(err)
}

func newDownloadPipe(d *s3manager.Downloader) *downloadPipe {
	if d.Concurrency != 1 {
		panic("downloader must have Concurrency = 1")
	}
	readPipe, writePipe := io.Pipe()
	return &downloadPipe{
		downloader: d,
		reader:     readPipe,
		writer:     writePipe,
		buffer:     make([]byte, 0, d.PartSize),
	}
}
