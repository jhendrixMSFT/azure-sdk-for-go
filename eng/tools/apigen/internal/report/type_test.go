// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package report_test

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/printer"
	"os"
	"testing"
	"testing/fstest"

	"apigen/internal/loader"
	"apigen/internal/report"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTypes(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	source := `package sample

import "time"

type (
	hidden struct{ Exported int }
	Code string
	Empty struct{}
	Opaque struct{ secret int }

	// Container holds two values.
	Container[A, B any] struct {
		First A
		Second B
	}

	Visible struct {
		*Container[string, int]
		*time.Timer
		hidden
		// Value is public.
		Value string ` + "`json:\"value\"`" + `
		private, Count int ` + "`json:\"count\"`" + `
		Extra struct{ private bool }
	}

	Alias[T any] = map[string]chan<- *[]T
	Instant = time.Time
	Buffer [2]Code
	Callback func(input struct{ Public int; private string }) (result int)
	Constraint interface{ ~int | ~int64 }
)

func Consume(value struct{ private int }) {}
`
	require.NoError(t, os.CopyFS(dir, fstest.MapFS{
		"go.mod":    {Data: []byte("module example.com/sample\n\ngo 1.26.0\n")},
		"sample.go": {Data: []byte(source)},
	}))
	loaded, err := loader.Load(t.Context(), dir)
	require.NoError(t, err)
	root := loaded.Packages[0]
	var before bytes.Buffer
	require.NoError(t, format.Node(&before, root.Fset, root.Syntax[0]))

	packages, err := report.ExtractPackages(loaded)
	require.NoError(t, err)
	require.Len(t, packages, 1)

	var names []string
	declarations := make(map[string]report.Type)
	rendered := make(map[string]string)
	for _, typ := range packages[0].Types {
		names = append(names, typ.Name)
		declarations[typ.Name] = typ
		var output bytes.Buffer
		require.NotNil(t, typ.Comments)
		require.NoError(t, format.Node(&output, packages[0].FileSet, &printer.CommentedNode{
			Node:     typ.Decl,
			Comments: typ.Comments,
		}))
		_, err := format.Source(append([]byte("package sample\n"), output.Bytes()...))
		require.NoError(t, err, "invalid type declaration for %s", typ.Name)
		rendered[typ.Name] = output.String()
	}
	assert.Equal(t, []string{
		"Alias", "Buffer", "Callback", "Code", "Constraint",
		"Container", "Empty", "Instant", "Opaque", "Visible",
	}, names)
	assert.Equal(t, "type Alias[T any] = map[string]chan<- *[]T", rendered["Alias"])
	assert.Equal(t, "type Instant = time.Time", rendered["Instant"])
	assert.Equal(t, "type Buffer [2]Code", rendered["Buffer"])
	assert.Equal(t, "type Constraint interface{ ~int | ~int64 }", rendered["Constraint"])
	assert.Contains(t, rendered["Callback"], "Public int")
	assert.NotContains(t, rendered["Callback"], "private")
	assert.NotContains(t, rendered["Container"], "Container holds two values")

	require.Len(t, declarations["Visible"].Decl.Specs, 1)
	spec, ok := declarations["Visible"].Decl.Specs[0].(*ast.TypeSpec)
	require.True(t, ok)
	structure, ok := spec.Type.(*ast.StructType)
	require.True(t, ok)
	require.Len(t, structure.Fields.List, 5)
	var fields []string
	for _, field := range structure.Fields.List {
		var output bytes.Buffer
		if len(field.Names) == 0 {
			require.NoError(t, format.Node(&output, packages[0].FileSet, field.Type))
			fields = append(fields, output.String())
		} else {
			fields = append(fields, field.Names[0].Name)
		}
	}
	assert.Equal(t, []string{
		"*Container[string, int]", "*time.Timer", "Value", "Count", "Extra",
	}, fields)
	require.NotNil(t, structure.Fields.List[2].Tag)
	assert.Equal(t, "`json:\"value\"`", structure.Fields.List[2].Tag.Value)
	require.NotNil(t, structure.Fields.List[3].Tag)
	assert.Equal(t, "`json:\"count\"`", structure.Fields.List[3].Tag.Value)
	assert.NotContains(t, rendered["Visible"], "Value is public")

	const marker = "// Contains no exported fields."
	assert.Contains(t, rendered["Opaque"], marker)
	assert.NotContains(t, rendered["Opaque"], "secret")
	assert.Empty(t, declarations["Empty"].Comments)
	require.Len(t, declarations["Visible"].Comments, 1, "only the nested opaque struct needs a marker")
	assert.Contains(t, rendered["Visible"], marker)

	require.Len(t, packages[0].Functions, 1)
	function := packages[0].Functions[0]
	var signature bytes.Buffer
	require.NoError(t, format.Node(&signature, packages[0].FileSet, &printer.CommentedNode{
		Node:     function.Decl,
		Comments: function.Comments,
	}))
	assert.Contains(t, signature.String(), marker)
	assert.NotContains(t, signature.String(), "private")
	_, err = format.Source(append([]byte("package sample\n"), signature.Bytes()...))
	require.NoError(t, err)

	var after bytes.Buffer
	require.NoError(t, format.Node(&after, root.Fset, root.Syntax[0]))
	assert.Equal(t, before.String(), after.String(), "type extraction must not mutate loaded syntax")
}
