// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"apigen/internal/loader"
	"apigen/internal/markdown"
	"apigen/internal/report"

	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	command := newRootCommand()
	if err := command.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(command.ErrOrStderr(), "Error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var output string
	command := &cobra.Command{
		Use:           "apigen <module-directory>",
		Short:         "Generate a Markdown review report of a Go module's public API",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, args []string) error {
			if output == "" {
				return fmt.Errorf("output must be a file path or - for stdout")
			}
			loaded, err := loader.Load(command.Context(), args[0])
			if err != nil {
				return err
			}
			packages, err := report.ExtractPackages(loaded)
			if err != nil {
				return err
			}
			metadata := report.ExtractModule(loaded)
			if output == "-" {
				return markdown.Write(command.OutOrStdout(), metadata, packages)
			}
			return writeReportFile(output, metadata, packages)
		},
	}
	command.Flags().StringVarP(&output, "output", "o", "-", "Write to a file instead of stdout (-)")
	return command
}
