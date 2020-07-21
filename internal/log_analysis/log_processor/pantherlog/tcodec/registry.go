package tcodec

import (
	"errors"
	"time"
)

var (
	defaultRegistry = &Registry{
		codecs: map[string]TimeCodec{
			"unix":    UnixSecondsCodec(),
			"unix_ms": UnixMillisecondsCodec(),
			"rfc3339": LayoutCodec(time.RFC3339Nano),
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
