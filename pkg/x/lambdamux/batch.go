package lambdamux

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
	"context"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

type batchJobs struct {
	jobs   []batchJob
	buffer []byte
}

type batchJob struct {
	name       string
	handler    Handler
	start, end int
}

var batchPool = &sync.Pool{
	New: func() interface{} {
		return &batchJobs{}
	},
}

func borrowBatch() *batchJobs {
	return batchPool.Get().(*batchJobs)
}
func (b *batchJobs) Recycle() {
	if b == nil {
		return
	}
	for i := range b.jobs {
		b.jobs[i] = batchJob{}
	}
	batchPool.Put(b)
}

func (m *Mux) runBatch(ctx context.Context, b *batchJobs) ([]byte, error) {
	// Run the batch
	jsonAPI := resolveJSON(m.JSON)
	w := jsonAPI.BorrowStream(nil)
	defer jsonAPI.ReturnStream(w)
	if err := b.Run(ctx, w); err != nil {
		return nil, err
	}

	// We need to make a copy of the buffer to return it
	out := make([]byte, w.Buffered())
	copy(out, w.Buffer())
	return out, nil
}

func (b *batchJobs) Run(ctx context.Context, w *jsoniter.Stream) error {
	w.WriteArrayStart()
	for i := range b.jobs {
		job := &b.jobs[i]
		payload := b.slicePayload(job.start, job.end)
		reply, err := job.handler.Invoke(ctx, payload)
		if err != nil {
			return errors.WithMessagef(err, "batch job %s %d/%d failed", job.name, i, len(b.jobs))
		}
		if i != 0 {
			w.WriteMore()
		}
		w.WriteVal(jsoniter.RawMessage(reply))
	}
	w.WriteArrayEnd()
	return nil
}

func (b *batchJobs) slicePayload(start, end int) (p []byte) {
	if 0 <= start && start < len(b.buffer) {
		p = b.buffer[start:]
		if 0 <= end && end <= len(p) {
			return p[:end]
		}
	}
	return nil
}

func (b *batchJobs) ReadJobs(mux *Mux, iter *jsoniter.Iterator) error {
	buffer := b.buffer[:0]
	jobs := b.jobs[:0]
	var jobIter *jsoniter.Iterator
	defer func() {
		if jobIter != nil {
			iter.Pool().ReturnIterator(jobIter)
		}
	}()
	for iter.ReadArray() {
		payload := iter.SkipAndReturnBytes()
		if jobIter == nil {
			jobIter = iter.Pool().BorrowIterator(payload)
		} else {
			jobIter.ResetBytes(payload)
		}
		jobPayload, name := mux.demux(jobIter, payload)
		if err := jobIter.Error; err != nil {
			return errors.Wrap(err, `invalid batch JSON payload`)
		}
		handler, err := mux.Get(name)
		if err != nil {
			return err
		}
		start := len(buffer)
		buffer = append(buffer, jobPayload...)
		jobs = append(jobs, batchJob{
			name:    name,
			handler: handler,
			start:   start,
			end:     len(buffer) - start,
		})
	}
	*b = batchJobs{
		buffer: buffer,
		jobs:   jobs,
	}
	return nil
}
