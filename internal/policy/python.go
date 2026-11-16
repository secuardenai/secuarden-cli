package policy

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

//go:embed python_guard.py
var pythonGuard string

func CheckRuntime() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "python3", "-I", "-c", "import ast, sys; assert sys.version_info >= (3, 8)").Run(); err != nil {
		return fmt.Errorf("Python decorator enforcement requires python3 >= 3.8 on the hook PATH")
	}
	return nil
}

func comparePython(ctx context.Context, before, after string, policies []Policy) error {
	input, _ := json.Marshal(map[string]any{"before": before, "after": after, "policies": policies})

	command := exec.CommandContext(ctx, "python3", "-I", "-c", pythonGuard)
	command.Stdin = strings.NewReader(string(input))
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("cannot evaluate Python syntax (invalid source, unavailable parser, or timeout)")
	}
	var result struct {
		Denied string `json:"denied"`
	}
	if json.Unmarshal(output, &result) != nil {
		return fmt.Errorf("invalid parser response")
	}
	if result.Denied != "" {
		return fmt.Errorf("%s", result.Denied)
	}
	return nil
}
