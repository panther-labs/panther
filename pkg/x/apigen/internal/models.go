package internal

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
	"bytes"
	"fmt"
	"go/types"
	"strings"

	"github.com/pkg/errors"
)

type Models struct {
	models map[string]types.Type
}

func NewModels() *Models {
	return &Models{
		models: map[string]types.Type{},
	}
}

func (m *Models) Write(buf *bytes.Buffer, pkg *types.Package) {
	qualifier := types.RelativeTo(pkg)
	for name, typ := range m.models {
		src := types.TypeString(typ, qualifier)
		src = fixTagQuotes(src)
		src = fmt.Sprintf(`type %s %s`, name, src)
		buf.WriteString(src)
	}
}

func fixTagQuotes(src string) string {
	fixed := make([]byte, 0, len(src))
	for i := 0; i < len(src); i++ {
		switch c := src[i]; c {
		case '"':
			fixed = append(fixed, '`')
		case '\\':
			i++
			fixed = append(fixed, src[i])
		default:
			fixed = append(fixed, c)
		}
	}
	return string(fixed)
}

func (m *Models) AddMethods(methods ...*Method) error {
	for _, method := range methods {
		if obj := method.Input; obj != nil {
			name := withSuffix(method.Name, "Input")
			if err := m.AddType(name, obj.Type()); err != nil {
				return err
			}
		}
		if obj := method.Output; obj != nil {
			name := withSuffix(method.Name, "Output")
			if err := m.AddType(name, obj.Type()); err != nil {
				return err
			}
		}
	}
	return nil
}

func withSuffix(name, suffix string) string {
	if strings.HasSuffix(name, suffix) {
		return name
	}
	return name + suffix
}

func (m *Models) AddType(name string, typ types.Type) error {
	if name == "" {
		named, ok := typ.(*types.Named)
		if !ok {
			return nil
		}
		name = named.Obj().Name()
	}
	model := modelType(typ)
	if model == nil {
		return errors.Errorf("invalid model type %s %s", name, typ)
	}
	switch typ := model.Underlying().(type) {
	case *types.Struct:
		m.models[name] = typ
		for i := 0; i < typ.NumFields(); i++ {
			field := typ.Field(i)
			if err := m.AddType("", field.Type()); err != nil {
				return errors.WithMessagef(err, "invalid struct field %s", field.Name())
			}
		}
	case *types.Basic:
		return nil
	default:
		return errors.New(`invalid model type`)
	}
	return nil
}

func modelType(typ types.Type) types.Type {
	switch typ := typ.Underlying().(type) {
	case *types.Pointer:
		return modelType(typ.Elem())
	case *types.Struct:
		return FlatStruct(typ)
	case *types.Array:
		return modelType(typ.Elem())
	case *types.Slice:
		return modelType(typ.Elem())
	case *types.Basic:
		return typ
	case *types.Map:
		key, ok := typ.Key().Underlying().(*types.Basic)
		if !ok {
			panic("invalid map key")
		}
		elem := modelType(typ.Elem())
		return types.NewMap(key, elem)
	default:
		panic("invalid model type")
	}
}

func FlatStruct(s *types.Struct) *types.Struct {
	return types.NewStruct(flattenStruct(nil, nil, s))
}

func flattenStruct(fields []*types.Var, tags []string, s *types.Struct) ([]*types.Var, []string) {
	for i := 0; i < s.NumFields(); i++ {
		field := s.Field(i)
		if !field.Exported() {
			continue
		}
		if field.Anonymous() {
			if typ, ok := field.Type().Underlying().(*types.Struct); ok {
				fields, tags = flattenStruct(fields, tags, typ)
				continue
			}
		}
		modelField := types.NewVar(field.Pos(), field.Pkg(), field.Name(), modelType(field.Type()))
		fields = append(fields, modelField)
		tags = append(tags, s.Tag(i))
	}
	return fields, tags
}
