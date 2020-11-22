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
)

// These values are very conservative defaults.
const DefaultReadBufferSize = 32 * 1024

type Downloader s3manager.Downloader

// Download creates a new reader that reads the contents of an S3 object.
// It uses a downloader to fetch the file in chunks to avoid connection resets.
// It prefetches the next chunk while the previous one is being processed.
func (dl Downloader) Download(ctx context.Context, input *s3.GetObjectInput) io.ReadCloser {
	if size := dl.PartSize; size <= 0 {
		dl.PartSize = s3manager.DefaultDownloadPartSize
	}
	// It is important to have a concurrency of 1. This forces the downloader to get the chunks in sequence.
	dl.Concurrency = 1
	parts := make(chan *bytes.Buffer, 1)
	r, w := io.Pipe()
	// Create a cancelable sub context so that the reader can abort the download
	ctx, cancel := context.WithCancel(ctx)
	dl.BufferProvider = newPrefetchProvider(ctx, w, int(dl.PartSize), parts)
	dpr := downloadReader{
		cancel:     cancel,
		pipeReader: r,
		// defer the downloading until the first call to Read
		download: func() {
			// We set channel size to 1 so that we prefetch the next chunk while the previous one is being processed
			// Close the parts channel once download finishes
			defer close(parts)
			// Start the copying of buffers to the io.PipeWriter
			go copyBuffers(w, parts)
			// We pass a dummy WriterAt value so that we get a panic if the downloader uses the WriteAt method directly.
			_, err := s3manager.Downloader(dl).DownloadWithContext(ctx, &nopWriterAt{}, input)
			// If an error occurs it will show up in the io.PipeReader side.
			// Otherwise an io.EOF will be shown to the io.PipeReader side.
			if err != nil {
				_ = w.CloseWithError(err)
			}
		},
	}

	return &dpr
}

func copyBuffers(w *io.PipeWriter, parts <-chan *bytes.Buffer) {
	var err error
	defer func() {
		_ = w.CloseWithError(err) // pushes errors thru to reader
	}()
	for part := range parts {
		_, err := part.WriteTo(w)
		if err != nil {
			return
		}
		part.Reset()
		bufferPool.Put(part)
	}
}

type downloadReader struct {
	cancel     context.CancelFunc
	once       sync.Once
	download   func()
	pipeReader *io.PipeReader
}

var _ io.ReadCloser = (*downloadReader)(nil)

// Read implements io.ReadCloser
// It reads from the underlying io.PipeReader
func (dr *downloadReader) Read(p []byte) (n int, err error) {
	// This starts the downloading on first read
	dr.once.Do(dr.startDownloading)
	return dr.pipeReader.Read(p)
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
		cancel()
	}
	return dr.pipeReader.Close()
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
// We panic to assert that s3manager.Downloader does not write to the buffer directly.
func (b *chunkBuffer) Write(_ []byte) (int, error) {
	panic("the Write() method should not have been used directly")
}
