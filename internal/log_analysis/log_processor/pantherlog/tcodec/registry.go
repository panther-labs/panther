package tcodec

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
	"errors"
	"time"
)

var (
	defaultRegistry = &Registry{
		codecs: map[string]TimeCodec{
			"unix":    UnixSecondsCodec(),
			"unix_ms": UnixMillisecondsCodec(),
			"unix_us": UnixMicrosecondsCodec(),
			"unix_ns": UnixNanosecondsCodec(),
			"rfc3339": Join(LayoutCodec(time.RFC3339), LayoutCodec(time.RFC3339Nano)),
		},
	}
)

type Registry struct {
	codecs map[string]TimeCodec
}

func NewRegistry() *Registry {
	return &Registry{
		codecs: make(map[string]TimeCodec),
	}
}

func (r *Registry) MustRegister(name string, codec TimeCodec) {
	if err := r.Register(name, codec); err != nil {
		panic(err)
	}
}

func (r *Registry) Register(name string, codec TimeCodec) error {
	if codec == nil {
		return errors.New("nil codec")
	}
	if name == "" {
		return errors.New("anonymous time codec")
	}
	if _, duplicate := r.codecs[name]; duplicate {
		return errors.New("duplicate time codec " + name)
	}
	r.set(name, codec)
	return nil
}

func (r *Registry) set(name string, codec TimeCodec) {
	if r.codecs == nil {
		r.codecs = make(map[string]TimeCodec)
	}
	r.codecs[name] = codec
}

func (r *Registry) Lookup(name string) TimeCodec {
	return r.codecs[name]
}

func (r *Registry) Extend(others ...*Registry) {
	for _, other := range others {
		if other == nil {
			continue
		}
		for name, codec := range other.codecs {
			r.set(name, codec)
		}
	}
}

func Register(name string, codec TimeCodec) error {
	return defaultRegistry.Register(name, codec)
}

func MustRegister(name string, codec TimeCodec) {
	if err := Register(name, codec); err != nil {
		panic(err)
	}
}

func Lookup(name string) TimeCodec {
	return defaultRegistry.Lookup(name)
}

func DefaultRegistry() *Registry {
	return defaultRegistry
}
