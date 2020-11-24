package priorityq

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

// Inspired by https://github.com/jupp0r/go-priority-queue . That package had  no Remove() or Peek().

import (
	"container/heap"
)

// PriorityQueue represents the queue
type PriorityQueue struct {
	heap queue
}

// Len returns the number of elements in the queue.
func (p *PriorityQueue) Len() int {
	return p.heap.Len()
}

// Insert inserts a new element into the queue. No action is performed on duplicate elements.
func (p *PriorityQueue) Insert(v interface{}, priority float64) (duplicate bool) {
	if _, duplicate = p.heap.lookup[v]; duplicate {
		return duplicate
	}
	heap.Push(&p.heap, heapEntry{
		value:    v,
		priority: priority,
	})
	return duplicate
}

// Pop removes the element with the highest priority from the queue and returns it.
// In case of an empty queue, nil is returned.
func (p *PriorityQueue) Pop() interface{} {
	if p.heap.Len() == 0 {
		return nil
	}
	return heap.Pop(&p.heap)
}

// Peek returns the item that is on top of the heap but does not remove.
// In case of an empty queue, false is returned.
func (p *PriorityQueue) Peek() (interface{}, bool) {
	if len(p.heap.entries) > 0 {
		return p.heap.entries[0].value, true
	}
	return nil, false
}

// UpdatePriority changes the priority of a given item.
// If the specified item is not present in the queue, no action is performed.
func (p *PriorityQueue) UpdatePriority(x interface{}, newPriority float64) {
	index, ok := p.heap.lookup[x]
	if !ok {
		return
	}
	item := &p.heap.entries[index]

	// no change?
	if item.priority == newPriority {
		return
	}

	item.priority = newPriority
	heap.Fix(&p.heap, index)
}

// Remove removes the element.
func (p *PriorityQueue) Remove(x interface{}) {
	index, ok := p.heap.lookup[x]
	if !ok {
		return
	}
	heap.Remove(&p.heap, index)
}

var _ heap.Interface = (*queue)(nil)

type heapEntry struct {
	value    interface{}
	priority float64
}

type queue struct {
	entries []heapEntry
	lookup  map[interface{}]int
}

func (q *queue) Len() int {
	return len(q.entries)
}

func (q *queue) Less(i, j int) bool {
	a, b := &q.entries[i], &q.entries[j]
	return a.priority < b.priority
}

func (q *queue) Swap(i, j int) {
	a, b := q.entries[i], q.entries[j]
	q.entries[i], q.entries[j] = b, a
	q.lookup[a.value], q.lookup[b.value] = j, i
}

func (q *queue) Push(x interface{}) {
	if q.lookup == nil {
		q.lookup = make(map[interface{}]int)
	}
	entry := x.(heapEntry)
	q.lookup[entry.value] = len(q.entries)
	q.entries = append(q.entries, entry)
}

func (q *queue) Pop() interface{} {
	last := len(q.entries) - 1
	var item heapEntry
	if 0 <= last && last < len(q.entries) {
		item, q.entries = q.entries[last], q.entries[:last]
		delete(q.lookup, item.value)
		return item.value
	}
	return nil
}
