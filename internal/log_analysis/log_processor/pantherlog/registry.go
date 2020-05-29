package pantherlog

import (
	"github.com/pkg/errors"
	"sync"
)

// Registry is a collection of LogTypes.
// It is safe to use a registry from multiple go routines.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*LogType
}

func NewRegistry(logTypes ...LogType) (*Registry, error) {
	r := &Registry{}
	for _, logType := range logTypes {
		if err := r.Register(logType); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// MustGet gets a registered LogType or panics
func (r *Registry) MustGet(name string) *LogType {
	if logType := r.Get(name); logType != nil {
		return logType
	}
	panic(errors.Errorf("unregistered log type %q", name))
}

func (r *Registry) Get(name string) *LogType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// LogTypes returns all available log types in a registry
func (r *Registry) LogTypes() (logTypes []LogType) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, logType := range r.entries {
		logTypes = append(logTypes, *logType)
	}
	return
}

func (r *Registry) Register(entry LogType) error {
	if err := entry.Check(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, duplicate := r.entries[entry.Name]; duplicate {
		return errors.Errorf("duplicate log type entry %q", entry.Name)
	}
	if r.entries == nil {
		r.entries = make(map[string]*LogType)
	}
	r.entries[entry.Name] = &entry
	return nil
}

// Default registry for pantherlog package
var defaultRegistry = &Registry{}

// DefaultRegistry returns the default package wide registry for log types
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Get gets a LogType entry from the package wide registry
func Get(logType string) *LogType {
	return defaultRegistry.Get(logType)
}

// MustGet gets a LogType entry from the package wide registry and panics if `logType` is not registered
func MustGet(logType string) *LogType {
	return defaultRegistry.MustGet(logType)
}

// Register registers log type entries to the package wide registry returning the first error it encounters
func Register(entries ...LogType) error {
	for _, entry := range entries {
		if err := defaultRegistry.Register(entry); err != nil {
			return err
		}
	}
	return nil
}

// Register registers log type entries to the package wide registry panicking if an error occurs
func MustRegister(entries ...LogType) {
	if err := Register(entries...); err != nil {
		panic(err)
	}
}

// Available log types returns the available log types
func AvailableLogTypes() []LogType {
	return defaultRegistry.LogTypes()
}
