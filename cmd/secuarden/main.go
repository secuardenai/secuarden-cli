package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/secuardenai/secuarden-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var hookError *cmd.HookExitError
		if errors.As(err, &hookError) && hookError.Code > 0 {
			os.Exit(hookError.Code)
		}
		os.Exit(1)
	}
}
