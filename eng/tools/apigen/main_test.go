// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"apigen/internal/report"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommand(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := filepath.Join(t.TempDir(), "module with spaces")
	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, os.CopyFS(dir, fstest.MapFS{
		"go.mod":    {Data: []byte("module example.com/sample\n\ngo 1.26.0\n")},
		"sample.go": {Data: []byte("package sample\n\ntype Client struct{ Name string }\n")},
		"api.md":    {Data: []byte("existing draft\n")},
	}))
	var expected string
	t.Run("stdout", func(t *testing.T) {
		command := newRootCommand()
		command.SetArgs([]string{dir})
		var output, diagnostics bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&diagnostics)
		require.NoError(t, command.ExecuteContext(t.Context()))
		expected = output.String()
		assert.Contains(t, expected, "# sample\n")
		assert.Contains(t, expected, "## Package sample\n")
		assert.Contains(t, expected, "type Client struct")
		assert.Empty(t, diagnostics.String())
		draft, err := os.ReadFile(filepath.Join(dir, "api.md"))
		require.NoError(t, err)
		assert.Equal(t, "existing draft\n", string(draft))
	})
	t.Run("explicit stdout", func(t *testing.T) {
		command := newRootCommand()
		command.SetArgs([]string{dir, "--output", "-"})
		var output bytes.Buffer
		command.SetOut(&output)
		require.NoError(t, command.ExecuteContext(t.Context()))
		assert.Equal(t, expected, output.String())
	})
	t.Run("replace file", func(t *testing.T) {
		destination := filepath.Join(t.TempDir(), "api review.md")
		require.NoError(t, os.WriteFile(destination, []byte("old report\n"), 0o640))
		original, err := os.Stat(destination)
		require.NoError(t, err)
		command := newRootCommand()
		command.SetArgs([]string{dir, "-o", destination})
		var output bytes.Buffer
		command.SetOut(&output)
		require.NoError(t, command.ExecuteContext(t.Context()))
		assert.Empty(t, output.String())
		report, err := os.ReadFile(destination)
		require.NoError(t, err)
		assert.Equal(t, expected, string(report))
		updated, err := os.Stat(destination)
		require.NoError(t, err)
		assert.Equal(t, original.Mode().Perm(), updated.Mode().Perm())
		files, err := filepath.Glob(filepath.Join(filepath.Dir(destination), ".apigen-*.tmp"))
		require.NoError(t, err)
		assert.Empty(t, files)
	})
}

func TestCommandErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		message string
	}{
		{name: "missing module", args: []string{}, message: "accepts 1 arg(s), received 0"},
		{name: "extra module", args: []string{"first", "second"}, message: "accepts 1 arg(s), received 2"},
		{name: "unknown flag", args: []string{"--unknown"}, message: "unknown flag"},
		{name: "empty output", args: []string{"module", "--output="}, message: "output must be"},
		{name: "missing module file", args: []string{t.TempDir()}, message: "read module file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			command := newRootCommand()
			command.SetArgs(tt.args)
			var output bytes.Buffer
			command.SetOut(&output)
			require.ErrorContains(t, command.ExecuteContext(t.Context()), tt.message)
			assert.Empty(t, output.String())
		})
	}
}

func TestReportFileFailurePreservesDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api.md")
	require.NoError(t, os.WriteFile(path, []byte("existing report\n"), 0o644))
	err := writeReportFile(path, report.Module{
		Path:         "example.com/sample",
		Dependencies: []report.Dependency{{Path: "example.com/dependency"}},
	}, nil)
	require.ErrorContains(t, err, "no selected module version")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "existing report\n", string(content))
	files, err := filepath.Glob(filepath.Join(dir, ".apigen-*.tmp"))
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestReportFileRejectsDirectory(t *testing.T) {
	err := writeReportFile(t.TempDir(), report.Module{Path: "example.com/sample"}, nil)
	require.ErrorContains(t, err, "not a regular file")
}
