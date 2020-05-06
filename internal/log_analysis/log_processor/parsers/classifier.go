package parsers

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type parserEntry struct {
	*Metered
	LogType string
	order   int
}

type Classifier struct {
	errMessage         string
	numClassifications AtomicFloat
	numHit             AtomicFloat
	numMiss            AtomicFloat

	mu      sync.RWMutex
	entries []*parserEntry
	active  *parserEntry
}

func NewClassifier(logTypes ...LogType) *Classifier {
	q := &Classifier{}
	q.resetLocked(logTypes)
	return q
}

func (q *Classifier) Reset(logTypes ...LogType) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.resetLocked(logTypes)
}

func (q *Classifier) Active() string {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.active != nil {
		return q.active.LogType
	}
	return ""
}

func (q *Classifier) resetLocked(logTypes []LogType) {
	names := make([]string, len(logTypes))
	entries := make([]*parserEntry, len(logTypes))
	for i, logType := range logTypes {
		names[i] = logType.Name
		parser := logType.NewParser()
		entries[i] = &parserEntry{
			Metered: NewMetered(parser),
			LogType: logType.Name,
		}
	}
	*q = Classifier{
		entries:    entries,
		errMessage: fmt.Sprintf("failed to classify log as [%s]", strings.Join(names, ",")),
	}
}

func (q *Classifier) Parse(log string) ([]*Result, error) {
	q.numClassifications.Add(1)
	q.mu.Lock()
	if q.active != nil {
		result, err := q.active.Parse(log)
		if err == nil {
			q.mu.Unlock()
			q.numHit.Add(1)
			return result, nil
		}
		q.numMiss.Add(1)
		q.active.order += 1
		sort.Slice(q.entries, func(i, j int) bool {
			return q.entries[i].order < q.entries[j].order
		})
	}
	// add defer here to avoid allocation in the hot path
	defer q.mu.Unlock()

	for _, entry := range q.entries {
		if entry == q.active {
			continue
		}
		result, err := entry.Parse(log)
		if err == nil {
			entry.order = 0
			q.active = entry
			return result, nil
		}
		entry.order += 1
	}
	q.active = nil
	return nil, errors.New(q.errMessage)

}
func (q *Classifier) ParserStats() map[string]Stats {
	q.mu.RLock()
	defer q.mu.RUnlock()
	parsers := make(map[string]Stats, len(q.entries))
	for _, entry := range q.entries {
		stats := entry.Stats()
		parsers[entry.LogType] = stats
	}
	return parsers
}

func (q *Classifier) Stats() QueueStats {
	return QueueStats{
		NumHit:  q.numHit.Load(),
		NumMiss: q.numMiss.Load(),
		Parsers: q.ParserStats(),
	}
}

type QueueStats struct {
	NumHit  float64
	NumMiss float64
	Parsers map[string]Stats
}
