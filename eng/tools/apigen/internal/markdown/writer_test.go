// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package markdown_test

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"apigen/internal/loader"
	"apigen/internal/markdown"
	"apigen/internal/report"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrite(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	require.NoError(t, os.CopyFS(dir, fstest.MapFS{
		"go.mod": {Data: []byte("module example.com/sample/v2\n\ngo 1.26.0\n")},
		"sample.go": {Data: []byte(`package sample

import (
	"context"
	"example.com/sample/v2/internal/model"
)

func Identity[T any](value T) T { return value }

// Client sends requests.
type Client struct {
	name string

	state bool
}

func NewClient() (*Client, error) { return &Client{}, nil }
func (c *Client) Send(ctx context.Context, value string) error { return nil }

type ETag string

const (
	ETagZulu ETag = "z"
	ETagAny ETag = "*"
)

type Config struct {
	// Value is the configured value.
	Value *string ` + "`json:\"value,omitempty\"`" + `
	hidden bool
	// Enabled controls behavior.
	// It has a zero-value default.
	Enabled bool
}

var Default = Config{}
var Alternate = Config{Value: nil}

type Record = model.Record
`)},
		"internal/model/model.go": {Data: []byte(`package model

type Record struct {
	Name string
	hidden int
}

func (r *Record) Reset() {}
`)},
		"arm/policy/policy.go": {Data: []byte("package policy\n\ntype ARM string\n")},
		"policy/policy.go":     {Data: []byte("package policy\n\ntype Policy string\n")},
	}))
	loaded, err := loader.Load(t.Context(), dir)
	require.NoError(t, err)
	packages, err := report.ExtractPackages(loaded)
	require.NoError(t, err)
	metadata := report.ExtractModule(loaded)
	var output bytes.Buffer
	require.NoError(t, markdown.Write(&output, metadata, packages))
	expected, err := os.ReadFile(filepath.Join("testdata", "sample.golden"))
	require.NoError(t, err)
	assert.Equal(t, strings.ReplaceAll(string(expected), "\r\n", "\n"), output.String())

	var again bytes.Buffer
	require.NoError(t, markdown.Write(&again, metadata, packages))
	assert.Equal(t, output.String(), again.String(), "rendering must not mutate report declarations")
}

func TestWritePreservesMultilineInitializers(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	source := "package sample\n\nvar Alpha = `first\n\n  second`\nvar Beta = `last\n\ntail`\n"
	require.NoError(t, os.CopyFS(dir, fstest.MapFS{
		"go.mod":    {Data: []byte("module example.com/sample\n\ngo 1.26.0\n")},
		"sample.go": {Data: []byte(source)},
	}))
	loaded, err := loader.Load(t.Context(), dir)
	require.NoError(t, err)
	packages, err := report.ExtractPackages(loaded)
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, markdown.Write(&output, report.ExtractModule(loaded), packages))
	_, code, ok := strings.Cut(output.String(), "```go\n")
	require.True(t, ok)
	code, _, ok = strings.Cut(code, "```\n")
	require.True(t, ok)
	parsed, err := parser.ParseFile(token.NewFileSet(), "api.go", code, 0)
	require.NoError(t, err)
	values := make(map[string]string)
	for _, decl := range parsed.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			require.True(t, ok)
			require.Len(t, value.Values, 1)
			literal, ok := value.Values[0].(*ast.BasicLit)
			require.True(t, ok)
			text, err := strconv.Unquote(literal.Value)
			require.NoError(t, err)
			values[value.Names[0].Name] = text
		}
	}
	assert.Equal(t, map[string]string{
		"Alpha": "first\n\n  second",
		"Beta":  "last\n\ntail",
	}, values)
}

func TestWriteModuleAndErrors(t *testing.T) {
	t.Run("module without root package or go directive", func(t *testing.T) {
		var output bytes.Buffer
		require.NoError(t, markdown.Write(&output, report.Module{
			Path: "example.com/sample/v2",
			Dependencies: []report.Dependency{
				{Path: "example.com/dependency", Version: "v1.2.3"},
			},
		}, nil))
		assert.Equal(t, "# sample\n\n## Module\n\n```text\nmodule example.com/sample/v2\n\n"+
			"// Direct, non-test, non-standard-library dependencies only.\nrequire (\n"+
			"\texample.com/dependency v1.2.3\n)\n```\n", output.String())
	})
	t.Run("versionless dependency", func(t *testing.T) {
		var output bytes.Buffer
		err := markdown.Write(&output, report.Module{
			Path:         "example.com/sample",
			Dependencies: []report.Dependency{{Path: "example.com/dependency"}},
		}, nil)
		require.ErrorContains(t, err, "no selected module version")
		assert.Empty(t, output.String())
	})
	t.Run("format failure leaves output untouched", func(t *testing.T) {
		var output bytes.Buffer
		err := markdown.Write(&output, report.Module{Path: "example.com/sample"}, []report.Package{
			{Path: "example.com/sample", Name: "not a package name"},
		})
		require.ErrorContains(t, err, "format Go declarations")
		assert.Empty(t, output.String())
	})
	t.Run("output failure", func(t *testing.T) {
		failure := errors.New("output failed")
		err := markdown.Write(failingWriter{err: failure}, report.Module{Path: "example.com/sample"}, nil)
		require.ErrorIs(t, err, failure)
	})
	t.Run("short output", func(t *testing.T) {
		err := markdown.Write(failingWriter{}, report.Module{Path: "example.com/sample"}, nil)
		require.ErrorIs(t, err, io.ErrShortWrite)
	})
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}
