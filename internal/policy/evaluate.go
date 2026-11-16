package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Evaluate returns a denial reason, or empty when no policy objects to the call.
// A store/evaluation error is a denial, independent of passive capture settings.
func Evaluate(data []byte) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	policies, err := Load()
	if err != nil {
		return "Secuarden policy store unavailable or invalid; action denied"
	}
	if len(policies) == 0 {
		return ""
	}
	var raw struct {
		CWD       string          `json:"cwd"`
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if len(data) > MaxBytes || json.Unmarshal(data, &raw) != nil || !filepath.IsAbs(raw.CWD) {
		return "Secuarden cannot evaluate malformed or oversized tool input"
	}
	var input map[string]any
	_ = json.Unmarshal(raw.ToolInput, &input)
	var errEval error
	switch raw.ToolName {
	case "Read", "Glob", "Grep", "read_file", "list_dir", "search_query", "web_search":
		return ""
	case "Edit", "Write", "MultiEdit":
		path, _ := input["file_path"].(string)
		if path == "" {
			return "Secuarden cannot evaluate an edit without file_path"
		}
		before, absolute, err := readSource(raw.CWD, path)
		if err != nil {
			return "Secuarden cannot read edit target"
		}
		after := before
		if raw.ToolName == "Write" {
			value, ok := input["content"].(string)
			if !ok {
				return "Secuarden Write requires content"
			}
			after = value
		} else if raw.ToolName == "MultiEdit" {
			edits, ok := input["edits"].([]any)
			if !ok || len(edits) == 0 {
				return "Secuarden invalid MultiEdit"
			}
			for _, value := range edits {
				edit, ok := value.(map[string]any)
				if !ok {
					return "Secuarden invalid MultiEdit entry"
				}
				after, err = replace(after, edit)
				if err != nil {
					return err.Error()
				}
			}
		} else {
			after, err = replace(before, input)
			if err != nil {
				return err.Error()
			}
		}
		errEval = checkFile(ctx, path, absolute, before, after, policies)
	case "apply_patch":
		patch, _ := input["patch"].(string)
		if patch == "" {
			patch, _ = input["command"].(string)
		}
		if patch == "" {
			patch, _ = input["input"].(string)
		}
		if patch == "" {
			_ = json.Unmarshal(raw.ToolInput, &patch)
		}
		errEval = checkPatch(ctx, raw.CWD, patch, policies)
	default:
		return "Secuarden decorator policy: tool " + raw.ToolName + " is not evaluable in v0.1; shell commands and unsupported tools are blocked. Use Edit, Write or apply_patch"
	}
	if errEval != nil {
		return "Secuarden: " + errEval.Error()
	}
	return ""
}

func readSource(cwd, path string) (string, string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	if canonical, err := filepath.EvalSymlinks(path); err == nil {
		path = canonical
	}
	data, err := readBounded(path)
	if os.IsNotExist(err) {
		return "", path, nil
	}
	return string(data), path, err
}

func replace(before string, input map[string]any) (string, error) {
	old, ok := input["old_string"].(string)
	newText, newOK := input["new_string"].(string)
	if !ok || !newOK || old == "" {
		return "", fmt.Errorf("Secuarden edit requires nonempty old_string and new_string")
	}
	all, _ := input["replace_all"].(bool)
	count := strings.Count(before, old)
	if count == 0 || (!all && count != 1) {
		return "", fmt.Errorf("Secuarden edit cannot be applied unambiguously")
	}
	if all {
		return strings.ReplaceAll(before, old, newText), nil
	}
	return strings.Replace(before, old, newText, 1), nil
}

func checkFile(ctx context.Context, requested, path, before, after string, policies []Policy) error {
	// Protect the user-level rule store from direct agent file-write tools too.
	store, _ := StorePath()
	if path == store || strings.HasPrefix(path, filepath.Dir(store)+string(filepath.Separator)) {
		return fmt.Errorf("policy/configuration directory cannot be edited while enforcement is active")
	}
	if strings.EqualFold(filepath.Ext(path), ".py") || strings.EqualFold(filepath.Ext(requested), ".py") {
		return comparePython(ctx, before, after, policies)
	}
	return nil
}
