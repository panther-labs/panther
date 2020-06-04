package classification

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// ParserPriorityQueue contains parsers in priority order
type ParserPriorityQueue struct {
	items []*ParserQueueItem
}

func NewParserPriorityQueue(logTypes ...pantherlog.LogType) *ParserPriorityQueue {
	q := ParserPriorityQueue{}
	q.initialize(logTypes)
	return &q
}

// initialize adds all registered parsers to the priority queue
// All parsers have the same priority
func (q *ParserPriorityQueue) initialize(logTypes []pantherlog.LogType) {
	for _, entry := range logTypes {
		q.items = append(q.items, &ParserQueueItem{
			logType: entry.Name,
			parser:  entry.NewParser(),
			penalty: 1,
		})
	}
}

// ParserQueueItem contains all the information needed to initialize a schema.
type ParserQueueItem struct {
	logType string
	parser  pantherlog.LogParser
	// The smaller the number the higher the priority of the parser in the queue
	penalty int
}

// Len returns the length of the priority queue
func (q *ParserPriorityQueue) Len() int {
	return len(q.items)
}

// Less compares two items of the priority queue
func (q *ParserPriorityQueue) Less(i, j int) bool {
	return q.items[i].penalty < q.items[j].penalty
}

// Swap swaps two items in the priority queue
func (q *ParserPriorityQueue) Swap(i, j int) {
	q.items[i], q.items[j] = q.items[j], q.items[i]
}

// Push adds an element to the end of the SchemaQueue
func (q *ParserPriorityQueue) Push(x interface{}) {
	q.items = append(q.items, x.(*ParserQueueItem))
}

// Pop removes the last element of the queue
func (q *ParserPriorityQueue) Pop() interface{} {
	n := len(q.items)
	item := q.items[n-1]
	q.items[n-1] = nil // avoid memory leak
	q.items = q.items[0 : n-1]
	return item
}

// Peek returns the item with the higher priority without removing it
func (q *ParserPriorityQueue) Peek() *ParserQueueItem {
	return q.items[0]
}
