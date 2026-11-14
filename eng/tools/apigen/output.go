// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"apigen/internal/markdown"
	"apigen/internal/report"
)

func writeReportFile(path string, metadata report.Module, packages []report.Package) (result error) {
	mode := os.FileMode(0o644)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output path %q is not a regular file", path)
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path %q: %w", path, err)
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".apigen-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary report for %q: %w", path, err)
	}
	temporary := file.Name()
	defer func() {
		if file != nil {
			if err := file.Close(); err != nil {
				result = errors.Join(result, fmt.Errorf("close temporary report: %w", err))
			}
		}
		if temporary != "" {
			if err := os.Remove(temporary); err != nil {
				result = errors.Join(result, fmt.Errorf("remove temporary report %q: %w", temporary, err))
			}
		}
	}()

	if err := markdown.Write(file, metadata, packages); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("set report permissions: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary report: %w", err)
	}
	err = file.Close()
	file = nil
	if err != nil {
		return fmt.Errorf("close temporary report: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace output file %q: %w", path, err)
	}
	temporary = ""
	return nil
}
