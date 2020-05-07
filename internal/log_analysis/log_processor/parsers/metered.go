package parsers

import (
	"math"
	"sync/atomic"
	"time"
)

// Stats holds stats for a parser.
// Metrics are stored as float64 to easily be able to provide rates (ie B/s, RPS etc) and averages.
type Stats struct {
	TotalTimeSeconds float64
	NumBytes         float64 // input bytes
	NumLines         float64 // input records
	NumResults       float64 // output records
	NumErrors        float64
}

// Throughput returns the bytes per second throughput of a parser
func (s *Stats) Throughput() float64 {
	return s.NumBytes / s.TotalTimeSeconds
}

// AvgParseTimeSeconds returns the average number of seconds spent parsing a single line
func (s *Stats) AvgParseTimeSeconds() float64 {
	return s.TotalTimeSeconds / s.NumLines
}

// Metered is a log parser wrapper that keeps track of metrics.
// Metrics can be retrieved safely from different goroutines.
type Metered struct {
	parser            Interface
	totalTimeSeconds  AtomicFloat
	numBytesProcessed AtomicFloat
	numErrors         AtomicFloat
	numResults        AtomicFloat
	numLines          AtomicFloat
}

// Stats returns stats for the inner parser
func (m *Metered) Stats() Stats {
	return Stats{
		TotalTimeSeconds: m.totalTimeSeconds.Load(),
		NumBytes:         m.numBytesProcessed.Load(),
		NumLines:         m.numLines.Load(),
		NumResults:       m.numResults.Load(),
		NumErrors:        m.numLines.Load(),
	}
}

// Parser returns the wrapped parser
func (m *Metered) Parser() Interface {
	return m.parser
}

// NewMetered wraps a parser tracking metrics
func NewMetered(parser Interface) *Metered {
	// Garbage in, garbage out
	if parser == nil {
		return nil
	}
	// Avoid double wrapping
	if m, ok := parser.(*Metered); ok {
		return m
	}
	return &Metered{
		parser: parser,
	}
}

// Parse implements parsers.Interface
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

// AtomicFloat keeps track of some metric
type AtomicFloat struct {
	value uint64
}

// Load loads the value of the metric
func (a *AtomicFloat) Load() float64 {
	return math.Float64frombits(atomic.LoadUint64(&a.value))
}

// Add adds some diff to the value
func (a *AtomicFloat) Add(d float64) {
	for {
		original := atomic.LoadUint64(&a.value)
		next := math.Float64bits(math.Float64frombits(original) + d)
		if atomic.CompareAndSwapUint64(&a.value, original, next) {
			return
		}
	}
}
