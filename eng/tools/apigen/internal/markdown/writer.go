// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Package markdown renders API review reports as Markdown.
package markdown

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/printer"
	"go/scanner"
	"go/token"
	"io"
	"path"
	"strconv"
	"strings"

	"apigen/internal/report"

	"golang.org/x/mod/module"
)

// Write renders module metadata and public packages using the API review format.
// Its inputs must come from report extraction. Rendering completes before any
// output is written; formatting and output errors are returned to the caller.
func Write(output io.Writer, metadata report.Module, packages []report.Package) error {
	prefix, _, ok := module.SplitPathVersion(metadata.Path)
	if !ok {
		return fmt.Errorf("invalid module path %q", metadata.Path)
	}
	title := path.Base(prefix)
	for _, pkg := range packages {
		if pkg.Path == metadata.Path {
			title = pkg.Name
			break
		}
	}

	var document bytes.Buffer
	fmt.Fprintf(&document, "# %s\n\n## Module\n\n```text\nmodule %s\n", title, metadata.Path)
	if metadata.GoVersion != "" {
		fmt.Fprintf(&document, "\ngo %s\n", metadata.GoVersion)
	}
	if len(metadata.Dependencies) > 0 {
		document.WriteString("\n// Direct, non-test, non-standard-library dependencies only.\nrequire (\n")
		for _, dependency := range metadata.Dependencies {
			if dependency.Version == "" {
				return fmt.Errorf("dependency %q has no selected module version", dependency.Path)
			}
			fmt.Fprintf(&document, "\t%s %s\n", dependency.Path, dependency.Version)
		}
		document.WriteString(")\n")
	}
	document.WriteString("```\n")

	for _, pkg := range packages {
		name := pkg.Name
		if pkg.Path != metadata.Path {
			if !strings.HasPrefix(pkg.Path, metadata.Path+"/") {
				return fmt.Errorf("package %q is outside module %q", pkg.Path, metadata.Path)
			}
			name = strings.TrimPrefix(pkg.Path, metadata.Path+"/")
		}
		source, err := packageSource(pkg)
		if err != nil {
			return fmt.Errorf("render package %q: %w", pkg.Path, err)
		}
		fmt.Fprintf(&document, "\n## Package %s\n\n```go\n", name)
		document.Write(source)
		document.WriteString("```\n")
	}
	if _, err := document.WriteTo(output); err != nil {
		return fmt.Errorf("write API report: %w", err)
	}
	return nil
}

func packageSource(pkg report.Package) ([]byte, error) {
	writer := packageWriter{fileSet: pkg.FileSet}
	fmt.Fprintf(&writer.source, "package %s\n\n", pkg.Name)
	if len(pkg.Imports) > 0 {
		writer.source.WriteString("import (\n")
		for i, entry := range pkg.Imports {
			if i > 0 && pkg.Imports[i-1].Standard != entry.Standard {
				writer.source.WriteByte('\n')
			}
			writer.source.WriteByte('\t')
			if entry.Name != "" {
				fmt.Fprintf(&writer.source, "%s ", entry.Name)
			}
			fmt.Fprintln(&writer.source, strconv.Quote(entry.Path))
		}
		writer.source.WriteString(")\n\n")
	}
	if err := writer.functions(pkg.Functions); err != nil {
		return nil, err
	}
	if err := writer.constants(pkg.Constants); err != nil {
		return nil, err
	}
	if err := writer.variables(pkg.Variables); err != nil {
		return nil, err
	}
	for _, typ := range pkg.Types {
		if typ.AliasOf != "" {
			fmt.Fprintf(&writer.source, "// Alias of %s.\n", typ.AliasOf)
		}
		text, err := writer.node(typ.Decl, typ.Comments)
		if err != nil {
			return nil, fmt.Errorf("type %q: %w", typ.Name, err)
		}
		writer.source.WriteString(text)
		writer.source.WriteString("\n\n")
		if err := writer.constants(typ.Constants); err != nil {
			return nil, err
		}
		if err := writer.variables(typ.Variables); err != nil {
			return nil, err
		}
		if err := writer.functions(typ.Functions); err != nil {
			return nil, err
		}
		if err := writer.functions(typ.Methods); err != nil {
			return nil, err
		}
	}
	source, err := format.Source(writer.source.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format Go declarations: %w", err)
	}
	return source, nil
}

type packageWriter struct {
	fileSet *token.FileSet
	source  bytes.Buffer
}

func (w *packageWriter) node(node ast.Node, comments []*ast.CommentGroup) (string, error) {
	var output bytes.Buffer
	if err := format.Node(&output, w.fileSet, &printer.CommentedNode{Node: node, Comments: comments}); err != nil {
		return "", err
	}
	return compactDeclaration(strings.TrimSpace(output.String()))
}

func compactDeclaration(text string) (string, error) {
	fileSet := token.NewFileSet()
	file := fileSet.AddFile("declaration.go", -1, len(text))
	var scan scanner.Scanner
	var scanError error
	scan.Init(file, []byte(text), func(pos token.Position, message string) {
		if scanError == nil {
			scanError = fmt.Errorf("scan declaration at %s: %s", pos, message)
		}
	}, scanner.ScanComments)
	protected := make(map[int]bool)
	for {
		pos, kind, literal := scan.Scan()
		if kind == token.EOF {
			break
		}
		if kind == token.STRING || kind == token.CHAR || kind == token.COMMENT {
			if count := strings.Count(literal, "\n"); count > 0 {
				first := file.Line(pos)
				for line := first; line <= first+count; line++ {
					protected[line] = true
				}
			}
		}
	}
	if scanError != nil {
		return "", scanError
	}
	var lines []string
	for i, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" || protected[i+1] {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func (w *packageWriter) functions(functions []report.Function) error {
	for _, function := range functions {
		text, err := w.node(function.Decl, function.Comments)
		if err != nil {
			return fmt.Errorf("function %q: %w", function.Name, err)
		}
		w.source.WriteString(text)
		w.source.WriteString("\n")
	}
	if len(functions) > 0 {
		w.source.WriteByte('\n')
	}
	return nil
}

func (w *packageWriter) constants(constants []report.Constant) error {
	var entries []string
	for _, item := range constants {
		entry := item.Name
		if item.TypeExpr != nil {
			text, err := w.node(item.TypeExpr, item.Comments)
			if err != nil {
				return fmt.Errorf("constant %q type: %w", item.Name, err)
			}
			entry += " " + text
		}
		value, err := constantExpression(item.Value)
		if err != nil {
			return fmt.Errorf("constant %q: %w", item.Name, err)
		}
		entries = append(entries, entry+" = "+value)
	}
	w.group("const", entries)
	return nil
}

func (w *packageWriter) variables(variables []report.Variable) error {
	var entries []string
	for _, variable := range variables {
		text, err := w.node(variable.Decl, variable.Comments)
		if err != nil {
			return fmt.Errorf("variable declaration: %w", err)
		}
		entry, ok := strings.CutPrefix(text, "var ")
		if !ok {
			return fmt.Errorf("expected a var declaration, got %q", text)
		}
		entries = append(entries, entry)
	}
	w.group("var", entries)
	return nil
}

func (w *packageWriter) group(keyword string, entries []string) {
	switch len(entries) {
	case 0:
		return
	case 1:
		fmt.Fprintf(&w.source, "%s %s\n\n", keyword, entries[0])
	default:
		fmt.Fprintf(&w.source, "%s (\n", keyword)
		for _, entry := range entries {
			fmt.Fprintf(&w.source, "\t%s\n", entry)
		}
		w.source.WriteString(")\n\n")
	}
}
