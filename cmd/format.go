package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func isTerminalOutput(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func colorOutput(w io.Writer) bool {
	return isTerminalOutput(w) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

func prepareCommandOutput(cmd *cobra.Command, _ []string) {
	if !isTerminalOutput(cmd.OutOrStdout()) || isHookCommand(cmd) || hasOutputFormatFlag(cmd, "json") || hasOutputFormatFlag(cmd, "md") {
		return
	}
	fmt.Fprintln(cmd.OutOrStdout())
}

func hasOutputFormatFlag(cmd *cobra.Command, name string) bool {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Value.String() == "true" {
		return true
	}
	if flag := cmd.InheritedFlags().Lookup(name); flag != nil && flag.Value.String() == "true" {
		return true
	}
	return false
}

func isHookCommand(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Name() == "hook" {
			return true
		}
	}
	return false
}
