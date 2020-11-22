package downloadpipe

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
	"sync"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	DownloadPartSize = 16 * 1024 * 1024 // the buffer size use for downloader
)

// Implements a pipe with the writer having the WriteAt() interface
type DownloadPipe struct {
	downloader     *s3manager.Downloader
	getObjectInput *s3.GetObjectInput
	reader         *io.PipeReader
	writer         *io.PipeWriter
	buffer         []byte // sized to part size
}

// these buffers are expensive, use a pool
var downloadPipePool = sync.Pool{
	New: func() interface{} {
		return &DownloadPipe{
			buffer: make([]byte, 0, DownloadPartSize),
		}
	},
}

func NewDownloadPipe(s3Client s3iface.S3API, getObjectInput *s3.GetObjectInput) *DownloadPipe {
	d := s3manager.NewDownloaderWithClient(s3Client)
	d.Concurrency = 1 // this MUST be 1 so the chunks come in order so they can be uncompressed
	d.PartSize = DownloadPartSize

	dp := downloadPipePool.Get().(*DownloadPipe)
	dp.getObjectInput = getObjectInput
	dp.downloader = d
	dp.reader, dp.writer = io.Pipe()
	dp.buffer = dp.buffer[:0] // reset slice
	return dp
}

func (dp *DownloadPipe) Close() error {
	downloadPipePool.Put(dp)
	return nil
}

func (dp *DownloadPipe) Run() {
	// while not important to processing, errors on close could indicate other issues
	var closeErr error
	defer func() {
		if closeErr != nil {
			zap.L().Warn("s3 download pipe close failed", zap.Error(closeErr))
		}
	}()

	_, err := dp.downloader.Download(dp, dp.getObjectInput)
	if err != nil {
		err = errors.Wrapf(err, "Download() failed for s3://%s/%s",
			*dp.getObjectInput.Bucket, *dp.getObjectInput.Key)
		// FIXME: logging here _should_ not be needed as the reader will fail and log. Since this is new code keeping for now
		zap.L().Error("s3 download failed", zap.Error(err))
		closeErr = dp.closeWriterWithError(err) // this will cause the reader to fail
	} else {
		closeErr = dp.closeWriter()
	}
}

func (dp *DownloadPipe) Read(p []byte) (n int, err error) {
	return dp.reader.Read(p)
}

func (dp *DownloadPipe) WriteAt(p []byte, offset int64) (n int, err error) {
	// we assume that offset is increasing or staying the same each call!
	// the writer expects to be able to re-write the chunk at the offset if there are errors reading from S3!
	bufferOffset := offset % dp.downloader.PartSize
	n = copy(dp.buffer[bufferOffset:bufferOffset+int64(len(p))], p)
	dp.buffer = dp.buffer[:len(dp.buffer)+n] // extend slice

	// flush?
	if len(dp.buffer) == cap(dp.buffer) {
		err := dp.flush()
		if err != nil {
			return n, err
		}
	}

	return n, err
}

func (dp *DownloadPipe) flush() error {
	_, err := dp.writer.Write(dp.buffer) // flush
	if err != nil {
		return err
	}
	dp.buffer = dp.buffer[:0] // reset slice
	return nil
}

func (dp *DownloadPipe) closeWriter() error {
	err := dp.flush()
	if err != nil {
		return dp.writer.CloseWithError(err)
	}
	return dp.writer.Close()
}

func (dp *DownloadPipe) closeWriterWithError(err error) error {
	return dp.writer.CloseWithError(err)
}
