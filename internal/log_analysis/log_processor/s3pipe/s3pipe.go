package s3pipe

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
	"context"
	"io"
	"sync"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
)

// These values are very conservative defaults.
const DefaultReadBufferSize = 32 * 1024

type Downloader s3manager.Downloader

// Download creates a new reader that reads the contents of an S3 object.
// It uses a downloader to fetch the file in chunks to enable recovery from read errors (e.g., connection resets).
// It prefetches the next chunk while the previous one is being processed.
// The chunk size is controlled by dl.PartSize and cost is 2 times dl.PartSize due to double buffer.
// Making the chunk size large reduces S3 API calls at the expense of memory.
func (dl Downloader) Download(ctx context.Context, input *s3.GetObjectInput) io.ReadCloser {
	// Create a cancelable sub context so that the reader can abort the download
	ctx, cancel := context.WithCancel(ctx)

	// All chunks will be written to this pipe.
	r, w := io.Pipe()
	// This channel will queue chunks.
	// Size is set to 1 so that the next chunk is being prefetched while the previous one is being processed.
	parts := make(chan *bytes.Buffer, 1)
	// We reset our copy of Downloader to read chunks in sequence and queue them into parts.
	dl.reset(ctx, w, parts)
	// We return a reader that will start downloading on first call to Read().
	// Chunks will be queued and written to the write part of the pipe.
	return &downloadReader{
		cancel: cancel,
		r:      r,
		// defer the downloading until the first call to Read
		download: func() {
			// Instrument downloads. The time will include time to parse the file as we do not close until final read.
			var err error
			// NOTE: dashboards depend on the operation name below! Do not change w/out updating dashboard
			operation := common.OpLogManager.Start("readS3Object", common.OpLogS3ServiceDim)
			defer func() {
				operation.Stop()
				operation.Log(err,
					// s3 dim info
					zap.String("bucket", *input.Bucket),
					zap.String("key", *input.Key),
					zap.Int64("partSize", dl.PartSize))
			}()
			// Close the parts channel once download finishes. This will signal copyBuffers goroutine to finish.
			// It is safe to close the channel when DownloadWithContext has returned since there won't be any more
			// calls to `push` after that.
			defer close(parts)
			// Start the copying of buffers to the io.PipeWriter. Closes the io.PipeWriter once finished.
			go copyBuffers(w, parts)
			// We pass a dummy WriterAt value so that we get a panic if the downloader uses the WriteAt method directly.
			dummyWriter := nopWriterAt{}
			// We cast our copy of the Downloader to s3manager.Downloader and start fetching chunks.
			_, err = s3manager.Downloader(dl).DownloadWithContext(ctx, &dummyWriter, input)
			// If an error occurs it will show up in the io.PipeReader side.
			// Otherwise an io.EOF will be shown to the io.PipeReader side.
			if err != nil {
				_ = w.CloseWithError(err)
			}
		},
	}
}

func (dl *Downloader) reset(ctx context.Context, w *io.PipeWriter, parts chan<- *bytes.Buffer) {
	// Ensure that dl.PartSize is set to a valid size
	if size := dl.PartSize; size <= 0 {
		dl.PartSize = s3manager.DefaultDownloadPartSize
	}
	// It is important to have a concurrency of 1. This forces the downloader to get the chunks in sequence.
	dl.Concurrency = 1
	// We override the BufferProvider to push parts to the io.PipeWriter directly.
	dl.BufferProvider = newPrefetchProvider(ctx, w, int(dl.PartSize), parts)
}

func copyBuffers(w *io.PipeWriter, parts <-chan *bytes.Buffer) {
	// It is safe to call this multiple times.
	// No reason to call CloseWithError as the only error here can only be that the pipe was already closed.
	defer w.Close()
	for part := range parts {
		_, err := part.WriteTo(w)
		// We recycle the buffer even if the write failed.
		part.Reset()
		bufferPool.Put(part)
		// An error means that the pipe was closed.
		if err != nil {
			return
		}
	}
}

type downloadReader struct {
	// r is the underlying pipe reader where data from being downloaded will be read from.
	r *io.PipeReader
	// cancel will abort the whole pipeline and clean up any resources
	cancel context.CancelFunc
	// once guards the download closure so it is only spawned one time on first Read()
	once sync.Once
	// download is a closure that will start downloading and pushing chunks to the pipe.
	download func()
}

var _ io.ReadCloser = (*downloadReader)(nil)

// Read implements io.ReadCloser
// It reads from the underlying io.PipeReader
func (dr *downloadReader) Read(p []byte) (n int, err error) {
	// This starts the downloading on first read
	dr.once.Do(dr.startDownloading)
	return dr.r.Read(p)
}

func (dr *downloadReader) startDownloading() {
	var download func()
	// Avoid memory leaks if the reader is kept longer by 'freeing' the download closure
	download, dr.download = dr.download, nil
	go download()
}

// Close implements io.ReadCloser
// It aborts the context used for downloading and closes the io.PipeReader
func (dr *downloadReader) Close() error {
	var cancel context.CancelFunc
	cancel, dr.cancel = dr.cancel, nil
	if cancel != nil {
		// We cancel the context *AFTER* we close the pipe.
		// This way context errors from the Download do not override the pipe closed error on Read().
		defer cancel()
	}
	return dr.r.Close()
}

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, DefaultReadBufferSize))
	},
}

type prefetchProvider struct {
	pipeWriter *io.PipeWriter
	partSize   int
	parts      chan<- *bytes.Buffer
	done       <-chan struct{}
}

func newPrefetchProvider(ctx context.Context, writer *io.PipeWriter, partSize int, parts chan<- *bytes.Buffer) *prefetchProvider {
	return &prefetchProvider{
		pipeWriter: writer,
		partSize:   partSize,
		parts:      parts,
		done:       ctx.Done(),
	}
}

var _ s3manager.WriterReadFromProvider = (*prefetchProvider)(nil)

func (p *prefetchProvider) push(part *bytes.Buffer) {
	select {
	case p.parts <- part:
	case <-p.done:
	}
}

// GetReadFrom implements s3manager.WriterReadFromProvider interface
func (p *prefetchProvider) GetReadFrom(_ io.Writer) (w s3manager.WriterReadFrom, cleanup func()) {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Grow(p.partSize)
	return &chunkBuffer{
			Buffer: buf,
		}, func() {
			// push the part into the queue once the full chunk is read.
			p.push(buf)
		}
}

type nopWriterAt struct{}

var _ io.WriterAt = (*nopWriterAt)(nil)

// WriteAt implements io.WriterAt interface
// The implementation is a stub.
// The S3 download manager will pass this instance to GetReadFrom and there we can redirect the data to the io.Pipe
func (*nopWriterAt) WriteAt(_ []byte, _ int64) (n int, err error) {
	panic("the WriteAt() method should not have been used directly")
}

type chunkBuffer struct {
	*bytes.Buffer
}

// ReadFrom implements io.ReaderFrom.
// It is called by s3manager.Downloader to read each chunk.
// If reading the chunk fails, it will be retried. To avoid partial reads escalating to corrupt data,
// we clear the buffer if an error occurs while reading.
func (b *chunkBuffer) ReadFrom(r io.Reader) (int64, error) {
	n, err := b.Buffer.ReadFrom(r)
	if err != nil {
		// Reset the buffer so errors while reading a chunk don't lead to partial reads through the pipe.
		b.Buffer.Reset()
	}
	return n, err
}

// Write implements io.Writer.
// The implementation is a stub.
// We panic to assert that s3manager.Downloader does not write to the buffer directly.
func (b *chunkBuffer) Write(_ []byte) (int, error) {
	panic("the Write() method should not have been used directly")
}
