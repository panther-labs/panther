package logschema

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
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

func Ref(target string) ValueSchema {
	return ValueSchema{
		Type:   TypeRef,
		Target: target,
	}
}

// MaxDepth is the maximum nesting depth for a ValueSchema
const MaxDepth = 64

// Resolve returns a copy of a ValueSchema with all references resolved from a manifest.
// It fails if a references cannot be resolved, if the nesting level exceeds MaxDepth or if there is a cyclic reference.
func Resolve(schema *Schema) (*ValueSchema, error) {
	path := make([]string, 0, MaxDepth)
	visited := make([]string, 0, MaxDepth)
	resolved, err := safeBuild(&ValueSchema{
		Type:   TypeObject,
		Fields: schema.Fields,
	}, schema.Definitions, path, visited)
	if err != nil {
		// Add stack here so we don't get huge recursive stack from safeBuild
		return nil, errors.WithStack(err)
	}
	return resolved, nil
}

func safeBuild(input *ValueSchema, manifest map[string]*ValueSchema, path, visited []string) (*ValueSchema, error) {
	switch input.Type {
	case TypeObject:
		if len(path) == cap(path) {
			return nil, fmt.Errorf("max nesting level (%d) exceeded", MaxDepth)
		}
		out := make([]FieldSchema, len(input.Fields))
		for i, field := range input.Fields {
			value, err := safeBuild(&field.ValueSchema, manifest, append(path, field.Name), visited)
			if err != nil {
				return nil, err
			}
			field.ValueSchema = *value
			out[i] = field
		}
		return &ValueSchema{
			Type:   TypeObject,
			Fields: out,
		}, nil
	case TypeArray:
		if len(path) == cap(path) {
			return nil, fmt.Errorf("max nesting level (%d) exceeded", MaxDepth)
		}
		item, err := safeBuild(input.Element, manifest, append(path, `[]`), visited)
		if err != nil {
			return nil, err
		}
		return &ValueSchema{
			Type:    TypeArray,
			Element: item,
		}, nil
	case TypeRef:
		if input.Target == "" {
			return nil, fmt.Errorf("empty reference %v", path)
		}
		target := input.Target
		if cycle := hasCycle(target, visited); cycle != nil {
			return nil, &CyclicReferenceError{
				path:  path,
				ref:   target,
				cycle: cycle,
			}
		}
		ref, ok := manifest[target]
		if !ok {
			return nil, fmt.Errorf("unresolved type reference %q", target)
		}
		return safeBuild(ref, manifest, path, append(visited, target))
	case TypeString:
		return &ValueSchema{
			Type:       TypeString,
			Indicators: append([]string(nil), input.Indicators...),
			Validate:   input.Validate,
		}, nil
	case TypeTimestamp:
		return &ValueSchema{
			Type:        TypeTimestamp,
			TimeFormat:  input.TimeFormat,
			IsEventTime: input.IsEventTime,
		}, nil
	default:
		return &ValueSchema{Type: input.Type}, nil
	}
}

func hasCycle(ref string, visited []string) []string {
	for i, v := range visited {
		if v == ref {
			return visited[i:]
		}
	}
	return nil
}

type CyclicReferenceError struct {
	path  []string
	ref   string
	cycle []string
}

func (e *CyclicReferenceError) Error() string {
	return fmt.Sprintf("cyclic reference %q at %q: %v", e.ref, e.path, e.cycle)
}
func (e *CyclicReferenceError) Path() string {
	return strings.Join(e.path, ",")
}
func (e *CyclicReferenceError) Cycle() []string {
	return e.cycle
}
func (e *CyclicReferenceError) Ref() string {
	return e.ref
}
