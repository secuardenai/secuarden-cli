package agent

import (
	"os"
	"path/filepath"
	"strings"
)

var installedExecutable = os.Executable

func hookExecutable() (string, error) {
	path, err := installedExecutable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
}

func isSecuardenCommand(command string) bool {
	if index := strings.LastIndex(command, " hook "); index >= 0 {
		command = command[:index]
	}
	command = strings.Trim(command, "\"'")
	command = strings.ReplaceAll(command, "'\\''", "'")
	return filepath.Base(command) == "secuarden"
}
