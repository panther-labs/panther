package parsers

import (
	"math"
	"sync/atomic"
	"time"
)

type Stats struct {
	TotalTimeSeconds float64
	NumBytes         float64 // input bytes
	NumLines         float64 // input records
	NumResults       float64 // output records
	NumErrors        float64
}

func (s *Stats) Throughput() float64 {
	return s.NumBytes / s.TotalTimeSeconds
}
func (s *Stats) LinesPerSecond() float64 {
	return s.NumLines / s.TotalTimeSeconds
}

type Metered struct {
	parser            Interface
	totalTimeSeconds  AtomicFloat
	numBytesProcessed AtomicFloat
	numErrors         AtomicFloat
	numResults        AtomicFloat
	numLines          AtomicFloat
}

func (m *Metered) Stats() Stats {
	return Stats{
		TotalTimeSeconds: m.totalTimeSeconds.Load(),
		NumBytes:         m.numBytesProcessed.Load(),
		NumLines:         m.numLines.Load(),
		NumResults:       m.numResults.Load(),
		NumErrors:        m.numLines.Load(),
	}
}

func NewMetered(parser Interface) *Metered {
	return &Metered{
		parser: parser,
	}
}

func (o *Metered) Parse(log string) (results []*Result, err error) {
	tm := time.Now()
	defer func() {
		o.numLines.Add(1)
		o.totalTimeSeconds.Add(time.Now().Sub(tm).Seconds())
		o.numBytesProcessed.Add(float64(len(log)))
		o.numResults.Add(float64(len(results)))
		if err != nil {
			o.numErrors.Add(1)
		}
	}()
	results, err = o.parser.Parse(log)
	return
}

type AtomicFloat struct {
	value uint64
}

func (a *AtomicFloat) Load() float64 {
	return math.Float64frombits(atomic.LoadUint64(&a.value))
}

func (a *AtomicFloat) Add(d float64) {
	for {
		original := atomic.LoadUint64(&a.value)
		next := math.Float64bits(math.Float64frombits(original) + d)
		if atomic.CompareAndSwapUint64(&a.value, original, next) {
			return
		}
	}
}
