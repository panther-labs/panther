package logtypes

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

// Default registry for pantherlog package
var defaultRegistry = &Registry{}

// DefaultRegistry returns the default package wide registry for log types
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// Register builds and registers log type entries to the package wide registry returning the first error it encounters
func Register(entries ...Builder) error {
	for _, entry := range entries {
		if _, err := defaultRegistry.Register(entry); err != nil {
			return err
		}
	}
	return nil
}

// Register builds and registers log type entries to the package wide registry panicking if an error occurs
func MustRegister(entries ...Builder) {
	for _, entry := range entries {
		// nolint:errcheck
		DefaultRegistry().MustRegister(entry)
	}
}

// RegisterJSON registers simple JSON log type entry to the package wide registry returning the first error it encounters
func RegisterJSON(desc Desc, eventFactory func() interface{}) (Entry, error) {
	return defaultRegistry.RegisterJSON(desc, eventFactory)
}

// MustRegisterJSON registers simple JSON log type entry to the package wide registry and panics if an error occurs
func MustRegisterJSON(desc Desc, eventFactory func() interface{}) Entry {
	entry, err := defaultRegistry.RegisterJSON(desc, eventFactory)
	if err != nil {
		panic(err)
	}
	return entry
}
