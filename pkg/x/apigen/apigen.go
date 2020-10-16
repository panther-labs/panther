package main

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
	"flag"
	"fmt"
	"go/format"
	"go/types"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/panther-labs/panther/pkg/x/apigen/internal"
)

const (
	typeLambdaClient = "lambdaclient"
	typeModels       = "models"
)

var (
	generatorName string
	printUsage    = func() {
		usage := fmt.Sprintf(`Usage: %s [OPTIONS] [SEARCH]...

Generate API client code

ARGS
	SEARCH		Go package patterns to search for TYPE (defaults to ".")
OPTIONS
`, generatorName)
		fmt.Fprint(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
	}

	opts = struct {
		Filename     *string
		Type         *string
		TargetAPI    *string `validate:"required,min=1"`
		MethodPrefix *string
		PackageName  *string
		Debug        *bool
	}{
		Filename:     flag.String(`out`, "", "Output file name (defaults to stdout)"),
		Type:         flag.String(`type`, typeLambdaClient, "Type of code to generate (lambdaclient|models)"),
		TargetAPI:    flag.String(`target`, "API", "Target API type name (defaults to 'API')"),
		MethodPrefix: flag.String(`prefix`, "", "Method name prefix (defaults to no prefix)"),
		PackageName:  flag.String(`pkg`, "", "Go package name to use (defaults to the package name of TYPE"),
		Debug:        flag.Bool(`debug`, false, "Print debug output to stderr"),
	}
)

func init() {
	// Get the executable name in the system
	generatorName = path.Base(os.Args[0])
	flag.Usage = printUsage
}

func main() {
	flag.Parse()

	logOut := ioutil.Discard
	if *opts.Debug {
		logOut = os.Stderr
	}
	logger := log.New(logOut, "", log.Lshortfile)

	apiName := *opts.TargetAPI
	if apiName == "" {
		fmt.Fprintf(flag.CommandLine.Output(), `%s: invalid 'target' option %q
Try '%s -help' for more information
`, apiName, generatorName, generatorName)
		os.Exit(1)
	}

	// Pass all args as patterns to search
	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"."}
	}

	pkgConfig := packages.Config{
		//nolint: staticcheck
		Mode:  packages.LoadSyntax,
		Tests: false,
	}

	if *opts.Debug {
		pkgConfig.Logf = logger.Printf
	}

	pkgs, err := packages.Load(&pkgConfig, patterns...)
	if err != nil {
		log.Fatalln("Failed to load packages", err)
	}
	index := pkgIndex(pkgs)
	apiObj := index.LookupType(apiName)
	if apiObj == nil {
		log.Fatalf("Failed to find %q in %s", apiName, strings.Join(patterns, ", "))
	}

	apiType, ok := apiObj.Type().(*types.Named)
	if !ok {
		log.Fatalf("invalid API object %s", apiObj)
	}
	clientPkg := apiType.Obj().Pkg()
	if name := *opts.PackageName; name != "" {
		clientPkg = types.NewPackage(".", *opts.PackageName)
	}

	methods, err := internal.ParseAPI(*opts.MethodPrefix, apiType)
	if err != nil {
		logger.Fatal(err)
	}

	var unformatted []byte

	switch *opts.Type {
	case typeModels:
		logger.Printf("Generating API models for %s with %d methods", apiName, len(methods))
		unformatted, err = GenerateModels(clientPkg, apiName, methods)
	case typeLambdaClient:
		logger.Printf("Generating API client %s.%sClient with %d methods", clientPkg.Name(), apiName, len(methods))
		unformatted, err = GenerateLambdaClient(clientPkg, apiName, methods)
	default:
		log.Fatalf("invalid type %q", *opts.Type)
	}
	if err != nil {
		logger.Fatal(err)
	}
	src, err := format.Source(unformatted)
	if err != nil {
		if *opts.Debug {
			logger.Println(string(unformatted))
		}
		log.Fatal(err)
	}
	if fileName := *opts.Filename; fileName != "" {
		if err := os.MkdirAll(path.Dir(fileName), 0755); err != nil {
			log.Fatalln("failed to create directory", err)
		}
		// nolint:gosec
		if err := ioutil.WriteFile(fileName, src, 0644); err != nil {
			log.Fatalln("failed to write", err)
		}
		return
	}
	if _, err := os.Stdout.Write(src); err != nil {
		log.Fatalln("failed to write", err)
	}
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

func GenerateModels(pkg *types.Package, apiName string, methods []*Method) ([]byte, error) {
	models := internal.NewModels()
	if err := models.AddMethods(methods...); err != nil {
		return nil, err
	}
	modelsBuffer := bytes.Buffer{}
	models.Write(&modelsBuffer, pkg)
	data := struct {
		Generator string
		Pkg       *types.Package
		API       string
		Methods   []*Method
		Models    string
		Imports   []*types.Package
	}{
		Generator: generatorName,
		Pkg:       pkg,
		API:       apiName,
		Methods:   methods,
		Models:    modelsBuffer.String(),
		Imports:   models.Imports(),
	}
	buffer := &bytes.Buffer{}
	if err := tplModels.Execute(buffer, data); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
func GenerateLambdaClient(pkg *types.Package, apiName string, methods []*Method) ([]byte, error) {
	data := struct {
		Generator string
		Pkg       *types.Package
		API       string
		Methods   []*Method
		Payload   string
		Imports   []*types.Package
	}{
		Generator: generatorName,
		Pkg:       pkg,
		API:       apiName,
		Methods:   methods,
		Payload:   generatePayload(pkg, apiName, methods),
		Imports:   methodsImports(pkg, methods...),
	}
	buffer := &bytes.Buffer{}
	if err := tplLambdaClient.Execute(buffer, data); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func generatePayload(pkg *types.Package, apiName string, methods []*Method) string {
	buf := bytes.Buffer{}
	buf.WriteString("type " + apiName + "Payload struct {\n")
	for _, m := range methods {
		buf.WriteString("  ")
		buf.WriteString(m.Name)
		buf.WriteString(" *")
		if m.Input != nil {
			buf.WriteString(resolveType(pkg, m.Input))
		} else {
			buf.WriteString("struct{}")
		}
		buf.WriteString(fmt.Sprintf(" `json:%q`\n", m.Name+",omitempty"))
	}
	buf.WriteString("}\n")
	return buf.String()
}

func resolveType(pkg *types.Package, obj types.Object) string {
	typ := obj.Type()
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	if named, ok := typ.(*types.Named); ok {
		if obj.Pkg().Path() == pkg.Path() {
			return named.Obj().Name()
		}
		return obj.Pkg().Name() + "." + named.Obj().Name()
	}
	return typ.String()
}

type Method = internal.Method

func methodsImports(pkg *types.Package, methods ...*Method) []*types.Package {
	index := make(map[string]*types.Package)
	for _, method := range methods {
		if obj := method.Input; obj != nil {
			index[obj.Pkg().Path()] = obj.Pkg()
		}
		if obj := method.Output; obj != nil {
			index[obj.Pkg().Path()] = obj.Pkg()
		}
	}
	var imports []*types.Package
	for _, imp := range index {
		if imp.Path() != pkg.Path() {
			imports = append(imports, imp)
		}
	}
	return imports
}
