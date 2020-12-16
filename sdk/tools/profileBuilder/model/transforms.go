// +build go1.9

// Copyright 2018 Microsoft Corporation and contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package model holds the business logic for the operations made available by
// profileBuilder.
//
// This package is not governed by the SemVer associated with the rest of the
// Azure-SDK-for-Go.
package model

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/mod/module"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/imports"
)

// ListDefinition represents a JSON file that contains a list of packages to include
type ListDefinition struct {
	Module  string           `json:"module"`
	Require []module.Version `json:"require"`
}

// BuildProfile takes a list of packages and creates a profile
func BuildProfile(modules []module.Version, profileDir string) {
	// limit the number of concurrent modules to alias
	semLimit := 8
	sem := make(chan struct{}, semLimit)
	wg := &sync.WaitGroup{}
	wg.Add(len(modules))
	for _, mod := range modules {
		go func(mod module.Version) {
			sem <- struct{}{}
			pkg, err := packages.Load(&packages.Config{
				Mode: packages.NeedModule,
			}, mod.Path)
			if err != nil {
				log.Fatalf("failed to load module %s: %v", mod.Path, err)
			}
			fs := token.NewFileSet()
			packages, err := parser.ParseDir(fs, pkg[0].Module.Dir, func(f os.FileInfo) bool {
				// exclude test files
				return !strings.HasSuffix(f.Name(), "_test.go")
			}, parser.ParseComments)
			<-sem
			if err != nil {
				log.Fatalf("failed to parse '%s': %v", pkg[0].Module.Dir, err)
			}
			if len(packages) < 1 {
				log.Fatalf("didn't find any packages in '%s'", pkg[0].Module.Dir)
			}
			if len(packages) > 1 {
				log.Fatalf("found more than one package in '%s'", pkg[0].Module.Dir)
			}
			for pkgName := range packages {
				astPkg := packages[pkgName]
				// trim any non-exported nodes
				if exp := ast.PackageExports(astPkg); !exp {
					log.Fatalf("package '%s' doesn't contain any exports", pkgName)
				}
				aliasDir := filepath.Join(profileDir, pkgName)
				if _, err := os.Stat(aliasDir); os.IsNotExist(err) {
					err = os.MkdirAll(aliasDir, os.ModeDir|0755)
					if err != nil {
						log.Fatalf("failed to create alias directory '%s': %v", aliasDir, err)
					}
				}
				aliasFile, err := NewAliasFile(astPkg, pkg[0].ID)
				if err != nil {
					log.Fatalf("failed to create alias package: %v", err)
				}
				writeAliasPackage(aliasFile, aliasDir)
			}
			wg.Done()
		}(mod)
	}
	wg.Wait()
	close(sem)
	log.Print(len(modules), " modules processed.")
}

// writeAliasPackage adds the MSFT Copyright Header, then writes the alias package to disk.
func writeAliasPackage(astFile *ast.File, outputPath string) {
	rawFile := &bytes.Buffer{}
	fs := token.NewFileSet()
	err := format.Node(rawFile, fs, astFile)
	if err != nil {
		log.Fatalf("failed to format AST: %v", err)
	}
	updated, err := imports.Process("", rawFile.Bytes(), nil)
	if err != nil {
		log.Fatalf("failed to process imports: %v", err)
	}
	aliasFilePath := filepath.Join(outputPath, astFile.Name.Name+".go")
	aliasFile, err := os.Create(aliasFilePath)
	if err != nil {
		log.Fatalf("error creating file: %v", err)
	}
	fmt.Fprintln(aliasFile, "// +build go1.13")
	fmt.Fprintln(aliasFile)

	fmt.Fprintln(aliasFile, `// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// This code was generated by a tool.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.`)
	fmt.Fprintln(aliasFile)

	log.Printf("Writing File: %s", aliasFilePath)
	aliasFile.Write(updated)
	if err != nil {
		log.Fatalf("error formatting file: %v", err)
	}
	aliasFile.Close()
}
