// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAllAPIReports(t *testing.T) {
	powershell, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell 7 is required to test the batch script")
	}
	t.Setenv("GOWORK", "off")
	binary := filepath.Join(t.TempDir(), "apigen")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	script, err := filepath.Abs("Generate-AllApiReports.ps1")
	require.NoError(t, err)

	t.Run("continues after failures and reports every failed module", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "SDK modules with spaces")
		require.NoError(t, os.Mkdir(root, 0o755))
		require.NoError(t, os.CopyFS(root, fstest.MapFS{
			"a-good/go.mod":  {Data: []byte("module example.com/first\n\ngo 1.26.0\n")},
			"a-good/main.go": {Data: []byte("package first\n\ntype Value string\n")},
			"b-bad/go.mod":   {Data: []byte("module example.com/bad\n\ngo 1.26.0\n")},
			"b-bad/main.go":  {Data: []byte("package bad\n\nvar Value = undefinedValue\n")},
			"b-bad/api.md":   {Data: []byte("existing report\n")},
			"c-good/go.mod":  {Data: []byte("module example.com/last\n\ngo 1.26.0\n")},
			"c-good/main.go": {Data: []byte("package last\n\ntype Value int\n")},
			"d-bad/go.mod":   {Data: []byte("module example.com/invalid\n\ngo invalid\n")},
			"d-bad/main.go":  {Data: []byte("package invalid\n")},
		}))
		command := exec.CommandContext(t.Context(), powershell, "-NoLogo", "-NoProfile", "-File", script,
			"-SdkRoot", root, "-ApigenPath", binary)
		output, err := command.CombinedOutput()
		var failure *exec.ExitError
		require.True(t, errors.As(err, &failure), "%v\n%s", err, output)
		assert.Equal(t, 1, failure.ExitCode())
		assert.Contains(t, string(output), "Failed to generate api.md for 2 of 4 modules:")
		assert.Contains(t, string(output), filepath.Join(root, "b-bad"))
		assert.Contains(t, string(output), filepath.Join(root, "d-bad"))
		for _, name := range []string{"a-good", "c-good"} {
			content, err := os.ReadFile(filepath.Join(root, name, "api.md"))
			require.NoError(t, err)
			assert.Contains(t, string(content), "## Module")
		}
		content, err := os.ReadFile(filepath.Join(root, "b-bad", "api.md"))
		require.NoError(t, err)
		assert.Equal(t, "existing report\n", string(content))
		_, err = os.Stat(filepath.Join(root, "d-bad", "api.md"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("reports success and includes nested modules", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.CopyFS(root, fstest.MapFS{
			"go.mod":          {Data: []byte("module example.com/outer\n\ngo 1.26.0\n")},
			"outer.go":        {Data: []byte("package outer\n\ntype Value int\n")},
			"nested/go.mod":   {Data: []byte("module example.com/inner\n\ngo 1.26.0\n")},
			"nested/inner.go": {Data: []byte("package inner\n\ntype Value string\n")},
		}))
		command := exec.CommandContext(t.Context(), powershell, "-NoLogo", "-NoProfile", "-File", script,
			"-SdkRoot", root, "-ApigenPath", binary)
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))
		assert.Contains(t, string(output), "Successfully generated api.md for all 2 modules.")
		for _, name := range []string{"", "nested"} {
			content, err := os.ReadFile(filepath.Join(root, name, "api.md"))
			require.NoError(t, err)
			assert.Contains(t, string(content), "## Module")
		}
	})
	t.Run("empty root is not reported as success", func(t *testing.T) {
		command := exec.CommandContext(t.Context(), powershell, "-NoLogo", "-NoProfile", "-File", script,
			"-SdkRoot", t.TempDir(), "-ApigenPath", binary)
		output, err := command.CombinedOutput()
		require.Error(t, err)
		assert.Contains(t, string(output), "No Go modules found")
		assert.NotContains(t, string(output), "Successfully generated")
	})
}
