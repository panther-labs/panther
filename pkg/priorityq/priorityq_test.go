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

import (
	"sort"
	"testing"
)

func TestPriorityQueue(t *testing.T) {
	pq := PriorityQueue{}
	elements := []float64{5, 3, 7, 8, 6, 2, 9}
	for _, e := range elements {
		pq.Insert(e, e)
	}

	sort.Float64s(elements)
	for _, e := range elements {
		peekItem, ok := pq.Peek()
		if !ok {
			t.Fatalf("peeck not found")
		}
		popItem := pq.Pop()

		if peekItem != popItem {
			t.Fatalf("peek != pop ")
		}

		i := popItem.(float64)
		if e != i {
			t.Fatalf("expected %v, got %v", e, i)
		}
	}
}

func TestPriorityQueueUpdate(t *testing.T) {
	pq := PriorityQueue{}
	pq.Insert("foo", 3)
	pq.Insert("bar", 4)
	pq.UpdatePriority("bar", 2)

	item := pq.Pop()
	if item.(string) != "bar" {
		t.Fatal("priority update failed")
	}
}

func TestPriorityQueueRemove(t *testing.T) {
	pq := PriorityQueue{}
	pq.Insert("foo", 5)
	pq.Insert("bar", 4)
	pq.Remove("foo") // next highest one is bar

	item := pq.Pop()
	if item.(string) != "bar" {
		t.Fatal("priority remove failed")
	}

	pq = PriorityQueue{}
	elements := []float64{5, 3, 7, 8, 6, 2, 9}
	for _, e := range elements {
		pq.Insert(e, e)
	}
	for _, e := range elements {
		pq.Remove(e)
	}
	if pq.Len() != 0 {
		t.Fatal("priority remove all failed")
	}
}

func TestPriorityQueueLen(t *testing.T) {
	pq := PriorityQueue{}
	if pq.Len() != 0 {
		t.Fatal("empty queue should have length of 0")
	}

	pq.Insert("foo", 1)
	pq.Insert("bar", 1)
	if pq.Len() != 2 {
		t.Fatal("queue should have length of 2 after 2 inserts")
	}
}

func TestDoubleAddition(t *testing.T) {
	pq := PriorityQueue{}
	pq.Insert("foo", 2)
	pq.Insert("bar", 3)
	pq.Insert("bar", 1)

	if pq.Len() != 2 {
		t.Fatal("queue should ignore inserting the same element twice")
	}

	item := pq.Pop()
	if item.(string) != "foo" {
		t.Fatal("queue should ignore duplicate insert, not update existing item")
	}
}

func TestPopEmptyQueue(t *testing.T) {
	pq := PriorityQueue{}
	item := pq.Pop()
	if item != nil {
		t.Fatal("should produce nil when performing pop on empty queue")
	}
}

func TestUpdateNonExistingItem(t *testing.T) {
	pq := PriorityQueue{}
	pq.Insert("foo", 4)
	pq.UpdatePriority("bar", 5)

	if pq.Len() != 1 {
		t.Fatal("update should not add items")
	}

	item := pq.Pop()
	if item.(string) != "foo" {
		t.Fatalf("update should not overwrite item, expected \"foo\", got \"%v\"", item.(string))
	}
}
