// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package report_test

import (
	"os"
	"testing"
	"testing/fstest"

	"apigen/internal/loader"
	"apigen/internal/report"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupDeclarations(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	require.NoError(t, os.CopyFS(dir, fstest.MapFS{
		"go.mod": {Data: []byte("module example.com/sample\n\ngo 1.26.0\n")},
		"sample.go": {Data: []byte(`package sample

import "example.com/sample/other"

type Widget struct{}
type Alias = Widget
type Box[T any] struct{ Value T }
type Mode string

const ZuluMode Mode = "z"
const AlphaMode Mode = "a"
const Bare = 1

var ZConfig = Widget{}
var AConfig *Widget
var First, Second = pairWidgets()
var MixedWidget, MixedNumber = mixed()
var AliasValue Alias

func NewWidget() (*Widget, error) { return &Widget{}, nil }
func NewBox[T any](value T) *Box[T] { return &Box[T]{Value: value} }
func NewAlias() Alias { return Alias{} }
func Widgets() []*Widget { return nil }
func External() other.Widget { return other.Widget{} }
func Generic[T any](value T) T { return value }
func Pair() (Widget, Widget) { return Widget{}, Widget{} }
func Both() (Widget, Mode) { return Widget{}, "" }
func (Widget) Zulu() {}
func (*Widget) Alpha() {}
func pairWidgets() (Widget, Widget) { return Widget{}, Widget{} }
func mixed() (Widget, int) { return Widget{}, 1 }
`)},
		"other/other.go": {Data: []byte("package other\n\ntype Widget struct{}\n")},
	}))
	loaded, err := loader.Load(t.Context(), dir)
	require.NoError(t, err)
	packages, err := report.ExtractPackages(loaded)
	require.NoError(t, err)
	require.NotEmpty(t, packages)
	pkg := packages[0]
	require.Equal(t, "example.com/sample", pkg.Path)

	groups := make(map[string]report.Type)
	for _, typ := range pkg.Types {
		groups[typ.Name] = typ
	}
	functionNames := func(functions []report.Function) []string {
		var names []string
		for _, function := range functions {
			names = append(names, function.Name)
		}
		return names
	}
	assert.Equal(t, []string{"Both", "External", "Generic", "Pair"}, functionNames(pkg.Functions))
	assert.Equal(t, []string{"NewWidget", "Widgets"}, functionNames(groups["Widget"].Functions))
	assert.Equal(t, []string{"Alpha", "Zulu"}, functionNames(groups["Widget"].Methods))
	assert.Equal(t, []string{"NewBox"}, functionNames(groups["Box"].Functions))
	assert.Equal(t, []string{"NewAlias"}, functionNames(groups["Alias"].Functions))

	var constantNames []string
	for _, constant := range groups["Mode"].Constants {
		constantNames = append(constantNames, constant.Name)
	}
	assert.Equal(t, []string{"AlphaMode", "ZuluMode"}, constantNames)
	require.Len(t, pkg.Constants, 1)
	assert.Equal(t, "Bare", pkg.Constants[0].Name)
	require.Len(t, groups["Mode"].Constants, 2)
	require.NotNil(t, groups["Mode"].Constants[0].TypeExpr, "grouping must retain import-ready type expressions")

	var variableNames []string
	for _, variable := range groups["Widget"].Variables {
		for _, object := range variable.Objects {
			variableNames = append(variableNames, object.Name())
		}
	}
	assert.Equal(t, []string{"AConfig", "First", "Second", "ZConfig"}, variableNames)
	require.Len(t, groups["Alias"].Variables, 1)
	assert.Equal(t, "AliasValue", groups["Alias"].Variables[0].Objects[0].Name())
	require.Len(t, pkg.Variables, 1)
	require.Len(t, pkg.Variables[0].Objects, 2)
	assert.Equal(t, "MixedWidget", pkg.Variables[0].Objects[0].Name())
	assert.Equal(t, "MixedNumber", pkg.Variables[0].Objects[1].Name())

	functionCount := len(pkg.Functions)
	constantCount := len(pkg.Constants)
	variableCount := len(pkg.Variables)
	for _, typ := range pkg.Types {
		functionCount += len(typ.Functions) + len(typ.Methods)
		constantCount += len(typ.Constants)
		variableCount += len(typ.Variables)
	}
	assert.Equal(t, 10, functionCount, "grouping must neither lose nor duplicate functions")
	assert.Equal(t, 3, constantCount, "grouping must neither lose nor duplicate constants")
	assert.Equal(t, 5, variableCount, "shared initializers must remain single declarations")
}
