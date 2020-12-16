// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// command line options common to all commands
var (
	clearOutdirFlag bool
	updateModFlag   bool
	outDir          string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "profileBuilder",
	Short: "Creates virtualized packages to simplify multi-API Version applications.",
	Long: `A profile is a virtualized set of packages, which attempts to hide the
complexity of choosing API Versions from customers who don't need the
flexiblity of separating the version of the Azure SDK for Go they're employing
from the version of Azure services they are targeting.

"profileBuilder" does the heavy-lifting of creating those virtualized packages.
Each of the sub-commands of profileBuilder applies a different strategy for
choosing which packages to include in the profile.
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&clearOutdirFlag, "clear-outdir", "c", false, "Removes all subdirectories in the output directory before writing a profile.")
	rootCmd.PersistentFlags().BoolVarP(&updateModFlag, "update", "u", false, "Pass -u to `go get` to update module versions.")
	rootCmd.PersistentFlags().StringVarP(&outDir, "outdir", "o", "", "The directory in which to output the generated profile.")
	rootCmd.MarkPersistentFlagRequired("outdir")
}
