package metrics

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

import "sync"

type Counter interface {
	With(dimensionValues ...string) Counter
	Add(delta float64)
}

// Counter is a counter. Observations are forwarded to a node
// object, and aggregated (summed) per timeseries.
type DimensionsCounter struct {
	name string
	unit string
	dvs  DimensionValues
	obs  func(name, unit string, dvs DimensionValues, value float64)
}

// With implements metrics.Counter.
func (d *DimensionsCounter) With(dvs ...string) Counter {
	return &DimensionsCounter{
		name: d.name,
		unit: d.unit,
		dvs:  d.dvs.With(dvs...),
		obs:  d.obs,
	}
}

// Add implements metrics.Counter.
func (d *DimensionsCounter) Add(delta float64) {
	d.obs(d.name, d.unit, d.dvs, delta)
}

// DimensionValues is a type alias that provides validation on its With method.
// Metrics may include it as a member to help them satisfy With semantics and
// save some code duplication.
type DimensionValues []string

// With validates the input, and returns a new aggregate labelValues.
func (lvs DimensionValues) With(dvs ...string) DimensionValues {
	if len(dvs)%2 != 0 {
		dvs = append(dvs, "unknown")
	}
	return append(lvs, dvs...)
}

// NewSpace returns an N-dimensional vector space.
func NewSpace() *Space {
	return &Space{}
}

// Space represents an N-dimensional vector space. Each name and unique label
// value pair establishes a new dimension and point within that dimension. Order
// matters, i.e. [a=1 b=2] identifies a different timeseries than [b=2 a=1].
type Space struct {
	mtx   sync.RWMutex
	nodes map[string]*node
}

// Observe locates the time series identified by the name and label values in
// the vector space, and appends the value to the list of observations.
func (s *Space) Observe(name, unit string, dvs DimensionValues, value float64) {
	s.nodeFor(name, unit).observe(dvs, value)
}

// Walk traverses the vector space and invokes fn for each non-empty time series
// which is encountered. Return false to abort the traversal.
func (s *Space) Walk(fn func(name, unit string, dvs DimensionValues, observations []float64) bool) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	for name, node := range s.nodes {
		name := name
		unit := node.unit
		f := func(dvs DimensionValues, observations []float64) bool { return fn(name, unit, dvs, observations) }
		if !node.walk(DimensionValues{}, f) {
			return
		}
	}
}

// Reset empties the current space and returns a new Space with the old
// contents. Reset a Space to get an immutable copy suitable for walking.
func (s *Space) Reset() *Space {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	n := NewSpace()
	n.nodes, s.nodes = s.nodes, n.nodes
	return n
}

func (s *Space) nodeFor(name, unit string) *node {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.nodes == nil {
		s.nodes = map[string]*node{}
	}
	n, ok := s.nodes[name]
	if !ok {
		n = &node{unit: unit}
		s.nodes[name] = n
	}
	return n
}

// node exists at a specific point in the N-dimensional vector space of all
// possible label values. The node collects observations and has child nodes
// with greater specificity.
type node struct {
	unit         string
	mtx          sync.RWMutex
	observations []float64
	children     map[pair]*node
}

type pair struct{ label, value string }

func (n *node) observe(dvs DimensionValues, value float64) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	if len(dvs) <= 0 {
		n.observations = append(n.observations, value)
		return
	}
	if len(dvs) < 2 {
		panic("too few metrics.DimensionValues; programmer error!")
	}
	head, tail := pair{dvs[0], dvs[1]}, dvs[2:]
	if n.children == nil {
		n.children = map[pair]*node{}
	}
	child, ok := n.children[head]
	if !ok {
		child = &node{unit: n.unit}
		n.children[head] = child
	}
	child.observe(tail, value)
}

func (n *node) walk(dvs DimensionValues, fn func(DimensionValues, []float64) bool) bool {
	n.mtx.RLock()
	defer n.mtx.RUnlock()
	if len(n.observations) > 0 && !fn(dvs, n.observations) {
		return false
	}
	for p, child := range n.children {
		if !child.walk(append(dvs, p.label, p.value), fn) {
			return false
		}
	}
	return true
}
