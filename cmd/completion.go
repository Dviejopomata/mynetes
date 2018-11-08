// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
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

package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var (
	completionShells = map[string]func(out io.Writer, cmd *cobra.Command) error{
		"bash": runCompletionBash,
	}
)

const completionDesc = `
Generate autocompletions script for Na-cli for the specified shell (bash).

This command can generate shell autocompletions. e.g.

	$ na-cli completion bash

Can be sourced as such

	$ source <(na-cli completion bash)
`

func runCompletionBash(out io.Writer, cmd *cobra.Command) error {
	return cmd.Root().GenBashCompletion(out)
}

var shells = []string{"bash"}

var completionCmd = &cobra.Command{
	Use:   "completion",
	Short: "A brief description of your command",
	Long:  completionDesc,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		return runCompletion(out, cmd, args)
	},
	ValidArgs: shells,
}

func runCompletion(out io.Writer, cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("shell not specified")
	}
	if len(args) > 1 {
		return fmt.Errorf("too many arguments, expected only the shell type")
	}
	run, found := completionShells[args[0]]
	if !found {
		return fmt.Errorf("unsupported shell type %q", args[0])
	}

	return run(out, cmd)
}

func init() {
	rootCmd.AddCommand(completionCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// completionCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// completionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
