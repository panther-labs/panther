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
		TargetAPI    *string `validate:"required,min=1"`
		MethodPrefix *string
		PackageName  *string
		Debug        *bool
	}{
		Filename:     flag.String(`out`, "", "Output file name (defaults to stdout)"),
		TargetAPI:    flag.String(`target`, "API", "Target API type name (defaults to 'API')"),
		MethodPrefix: flag.String(`prefix`, "", "Method name prefix (defaults to no prefix)"),
		PackageName:  flag.String(`pkg`, "", "Go package name to use (defaults to the package name of TYPE"),
		Debug:        flag.Bool(`debug`, false, "Print debug output to stderr"),
	}

	clientPkgPath = "github.com/panther-labs/panther/pkg/x/apigen/lambdaclient"
	clientPkgName = "lambdaclient"
	clientPkg     = types.NewPackage(clientPkgPath, clientPkgName)
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

	methods, err := internal.ParseAPI(*opts.MethodPrefix, apiType)
	if err != nil {
		logger.Fatal(err)
	}

	clientPkg := types.NewPackage(".", *opts.PackageName)
	if *opts.PackageName == "" {
		clientPkg = apiType.Obj().Pkg()
	}

	logger.Printf("Generating lambda client %s.TargetAPI for %s with %d methods", clientPkg.Name(), apiName, len(methods))
	src, err := GenerateClient(clientPkg, apiName, methods)
	if err != nil {
		logger.Fatal(err)
	}
	if !*opts.Debug {
		src, err = format.Source(src)
		if err != nil {
			log.Fatal(err)
		}
	}
	if fileName := *opts.Filename; fileName != "" {
		if err := os.MkdirAll(path.Dir(fileName), os.ModePerm); err != nil {
			log.Fatalln("failed to create directory", err)
		}
		if err := ioutil.WriteFile(fileName, src, os.ModePerm); err != nil {
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

func GenerateClient(pkg *types.Package, apiName string, methods []*Method) ([]byte, error) {
	models := internal.NewModels()
	if err := models.AddMethods(methods...); err != nil {
		return nil, err
	}
	modelsBuffer := bytes.Buffer{}
	models.Write(&modelsBuffer, pkg)
	data := struct {
		Generator string
		PkgName   string
		API       string
		Methods   []*Method
		Models    string
		Aliases   map[string]string
		Imports   []*types.Package
	}{
		Generator: generatorName,
		PkgName:   pkg.Name(),
		API:       apiName,
		Methods:   methods,
		Models:    modelsBuffer.String(),
		Imports: []*types.Package{
			clientPkg,
		},
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

type Method = internal.Method
