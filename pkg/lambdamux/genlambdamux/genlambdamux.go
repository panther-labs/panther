package main

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"go/types"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/tools/go/packages"
)

var (
	opts = struct {
		API          *string
		Filename     *string
		MethodPrefix *string
		PackageName  *string
		Debug        *bool
	}{
		API:          flag.String(`api`, "API", "API name"),
		Filename:     flag.String(`out`, "", "Output file name (defaults to stdout)"),
		MethodPrefix: flag.String(`prefix`, "", "Method name prefix"),
		PackageName:  flag.String(`pkg`, "", "Go package name to use"),
		Debug:        flag.Bool(`debug`, false, "Print debug output to stderr"),
	}

	typError   = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	typContext *types.Interface
)

func main() {
	logOut := ioutil.Discard
	if *opts.Debug {
		logOut = os.Stderr
	}
	logger := log.New(logOut, "", log.Lshortfile)
	flag.Parse()
	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"."}
	}

	pkgConfig := packages.Config{
		Mode:  packages.LoadSyntax,
		Tests: false,
	}

	if *opts.Debug {
		pkgConfig.Logf = logger.Printf
	}

	{
		pkgs, err := packages.Load(&pkgConfig, "context")
		if err != nil {
			logger.Fatalln("Failed to load packages", err)
		}
		index := pkgIndex(pkgs)
		typContext = index.LookupType("Context").Type().Underlying().(*types.Interface)
	}

	pkgs, err := packages.Load(&pkgConfig, patterns...)
	if err != nil {
		logger.Fatalln("Failed to load packages", err)
	}
	apiName := *opts.API
	index := pkgIndex(pkgs)
	apiObj := index.LookupType(apiName)
	if apiObj == nil {
		logger.Fatalf("Failed to find %q", apiName)
	}

	apiType, ok := apiObj.Type().(*types.Named)
	if !ok {
		logger.Fatalf("invalid API object %s", apiObj)
	}

	methods, err := ParseAPI(*opts.MethodPrefix, apiType)
	if err != nil {
		logger.Fatal(err)
	}
	clientPkg := types.NewPackage(".", *opts.PackageName)
	if *opts.PackageName == "" {
		clientPkg = apiType.Obj().Pkg()
	}

	logger.Printf("Generating lambda client %s.LambdaClient for %s with %d methods", clientPkg.Name(), apiName, len(methods))
	src, err := GenerateClient(clientPkg, apiName, methods)
	if err != nil {
		logger.Fatal(err)
	}
	src, err = format.Source(src)
	if err != nil {
		logger.Fatal(err)
	}
	if fileName := *opts.Filename; fileName != "" {
		if err := ioutil.WriteFile(fileName, src, os.ModePerm); err != nil {
			log.Fatalln("failed to write", err)
		}
	} else {
		if _, err := os.Stdout.Write(src); err != nil {
			log.Fatalln("failed to write", err)
		}
	}
	return
}

type pkgIndex []*packages.Package

func (pkgs pkgIndex) LookupType(name string) types.Object {
	for _, pkg := range pkgs {
		if obj := pkg.Types.Scope().Lookup(name); obj != nil {
			return obj
		}
	}
	return nil
}

func (pkgs pkgIndex) Find(name string) *packages.Package {
	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg
		}
	}
	return nil
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

func parseMethod(prefix string, method *types.Func) (*Method, error) {
	if !method.Exported() {
		return nil, nil
	}
	methodName := method.Name()
	if !strings.HasPrefix(methodName, prefix) {
		return nil, nil
	}
	m := Method{
		Name: strings.TrimPrefix(methodName, prefix),
	}
	sig := method.Type().(*types.Signature)
	if err := m.setSignature(sig); err != nil {
		return nil, fmt.Errorf(`invalid %s signature %s: %s`, methodName, sig, err)
	}

	return &m, nil
}

func (m *Method) setSignature(sig *types.Signature) error {
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

func GenerateClient(pkg *types.Package, apiName string, methods []*Method) ([]byte, error) {
	data := struct {
		Generator string
		PkgName   string
		API       string
		Methods   []*Method
		Aliases   map[string]string
		Imports   []*types.Package
	}{
		Generator: "genlambdamux",
		PkgName:   pkg.Name(),
		API:       apiName,
		Methods:   methods,
		Aliases:   methodAliases(pkg, methods...),
		Imports:   methodImports(pkg, methods...),
	}
	buffer := &bytes.Buffer{}
	if err := tplClient.Execute(buffer, data); err != nil {
		return nil, err
	}
	for _, m := range methods {
		var err error
		switch {
		case m.Input != nil && m.Output != nil:
			err = tplMethodInputOutput.Execute(buffer, m)
		case m.Input != nil:
			err = tplMethodInput.Execute(buffer, m)
		case m.Output != nil:
			err = tplMethodOutput.Execute(buffer, m)
		}
		if err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func typeAlias(obj types.Object, q types.Qualifier) string {
	if obj == nil {
		return ""
	}
	typ := obj.Type()
	if ptr, ok := typ.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	return types.TypeString(typ, q)
}

func methodAliases(pkg *types.Package, methods ...*Method) map[string]string {
	aliases := map[string]string{}
	q := types.RelativeTo(pkg)
	for _, m := range methods {
		if typ := typeAlias(m.Input, q); typ != "" {
			if alias := m.Name + "Input"; alias != typ {
				aliases[alias] = typ
			}
		}
		if typ := typeAlias(m.Output, q); typ != "" {
			if alias := m.Name + "Output"; alias != typ {
				aliases[alias] = typ
			}
		}
	}
	return aliases
}

func methodImports(pkg *types.Package, methods ...*Method) []*types.Package {
	imports := map[string]*types.Package{}
	for _, method := range methods {
		if method.Input != nil {
			inputPkg := method.Input.Pkg()
			if inputPkg.Path() != pkg.Path() {
				imports[pkg.Path()] = inputPkg
			}
		}
		if method.Output != nil {
			outputPkg := method.Output.Pkg()
			if outputPkg.Path() != pkg.Path() {
				imports[pkg.Path()] = outputPkg
			}
		}
	}
	pkgs := make([]*types.Package, 0, len(imports))
	for _, pkg := range imports {
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

type Method struct {
	API    string
	Input  types.Object
	Output types.Object
	Name   string
}

func isContext(typ types.Type) bool {
	return types.IsInterface(typ) && typ.Underlying().String() == typContext.String()
}
func isError(typ types.Type) bool {
	return types.IsInterface(typ) && typ.Underlying().String() == typError.String()
}
