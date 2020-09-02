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
	"fmt"
	"go/types"
	"log"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/tools/go/packages"
)

var (
	typError   = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	typContext *types.Interface
)

func init() {
	// Load context.Context
	pkgConfig := packages.Config{
		//nolint: staticcheck
		Mode: packages.LoadSyntax,
	}
	pkgs, err := packages.Load(&pkgConfig, "context")
	if err != nil {
		log.Fatalln("Failed to load context package", err)
	}
	for _, pkg := range pkgs {
		if pkg.Name == "context" {
			if obj := pkg.Types.Scope().Lookup("Context"); obj != nil {
				typContext = obj.Type().Underlying().(*types.Interface)
				return
			}
		}
	}
	panic("could not resolve context.Context type")
}

type Method struct {
	API    string
	Func   types.Object
	Input  types.Object
	Output types.Object
	Name   string
}

func ParseAPI(prefix string, api *types.Named) ([]*Method, error) {
	var methods []*Method
	numMethods := api.NumMethods()
	for i := 0; i < numMethods; i++ {
		method := api.Method(i)
		apiMethod, err := parseMethod(prefix, method)
		if err != nil {
			return nil, fmt.Errorf(`failed to parse %s.%s method: %s`, api.Obj().Name(), method.Name(), err)
		}
		if apiMethod == nil {
			continue
		}
		apiMethod.API = api.Obj().Name()
		methods = append(methods, apiMethod)
	}
	return methods, nil
}

func (m *Method) SetSignature(sig *types.Signature) error {
	if sig.Variadic() {
		return errors.New(`signature is variadic`)
	}

	inputs := sig.Params()
	switch numInputs := inputs.Len(); numInputs {
	case 0:
	case 1:
		input := inputs.At(0)
		if !isContext(input.Type()) {
			m.Input = input
		}
	case 2:
		if in := inputs.At(0); !isContext(in.Type()) {
			return fmt.Errorf(`signature param #1 of 2 (%s) is not context.Context`, in.Type())
		}
		m.Input = inputs.At(1)
	default:
		return fmt.Errorf(`too many (%d) params`, numInputs)
	}
	if m.Input != nil {
		if typ := m.Input.Type(); !isPtrToStruct(typ) {
			return fmt.Errorf(`param %s is not a pointer to struct`, typ)
		}
	}

	outputs := sig.Results()
	switch numResults := outputs.Len(); numResults {
	case 0:
	case 1:
		output := outputs.At(0)
		if !isError(output.Type()) {
			m.Output = output
		}
	case 2:
		if out := outputs.At(1); !isError(out.Type()) {
			return fmt.Errorf(`result #2 (%s) is not an error`, out.Type())
		}
		m.Output = outputs.At(0)
	default:
		return errors.New(`too many results`)
	}
	if m.Output != nil {
		if typ := m.Output.Type(); !isPtrToStruct(typ) {
			return fmt.Errorf(`result %s is not a pointer to struct`, typ)
		}
	}
	return nil
}

func isPtrToStruct(typ types.Type) bool {
	pt, isPointer := typ.(*types.Pointer)
	if !isPointer {
		return false
	}
	el := pt.Elem()
	if _, isStruct := el.Underlying().(*types.Struct); !isStruct {
		return false
	}
	return true
}

func parseMethod(prefix string, method *types.Func) (*Method, error) {
	if !method.Exported() {
		return nil, nil
	}
	methodName := method.Name()
	if !strings.HasPrefix(methodName, prefix) {
		return nil, nil
	}
	m := Method{
		Func: method,
		Name: strings.TrimPrefix(methodName, prefix),
	}
	sig := method.Type().(*types.Signature)
	if err := m.SetSignature(sig); err != nil {
		return nil, fmt.Errorf(`invalid %s signature %s: %s`, methodName, sig, err)
	}

	return &m, nil
}

func isContext(typ types.Type) bool {
	return types.IsInterface(typ) && typ.Underlying().String() == typContext.String()
}
func isError(typ types.Type) bool {
	return types.IsInterface(typ) && typ.Underlying().String() == typError.String()
}
