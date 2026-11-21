package capture

import (
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

const editTextCap = 8192

type editCapture struct {
	Path      string
	Before    string
	After     string
	Truncated bool
}

// editFromTool extracts the changed text for a file-write tool.
// Sensitive paths and metadata-only mode retain no body.
func editFromTool(toolName string, input map[string]interface{}, filePath, patch string, sensitive bool, privacyMode string) (editCapture, bool) {
	if sensitive || privacyMode == "metadata_only" || input == nil && patch == "" {
		return editCapture{}, false
	}
	var before, after string
	switch toolName {
	case "Edit":
		before, _ = input["old_string"].(string)
		after, _ = input["new_string"].(string)
	case "Write":
		after, _ = input["content"].(string)
	case "MultiEdit":
		edits, _ := input["edits"].([]any)
		var oldParts, newParts []string
		for _, value := range edits {
			edit, _ := value.(map[string]any)
			if edit == nil {
				continue
			}
			oldText, _ := edit["old_string"].(string)
			newText, _ := edit["new_string"].(string)
			oldParts = append(oldParts, oldText)
			newParts = append(newParts, newText)
		}
		before = strings.Join(oldParts, "\n")
		after = strings.Join(newParts, "\n")
	case "apply_patch":
		before, after = patchHunks(patch)
	default:
		return editCapture{}, false
	}
	if before == "" && after == "" {
		return editCapture{}, false
	}
	before, after, truncated := capEdit(before, after)
	if filePath == "" {
		filePath = events.ExtractFilePath(input)
	}
	return editCapture{Path: filePath, Before: before, After: after, Truncated: truncated}, true
}

func patchHunks(patch string) (string, string) {
	var before, after []string
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			after = append(after, strings.TrimPrefix(line, "+"))
			continue
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			before = append(before, strings.TrimPrefix(line, "-"))
		}
	}
	return strings.Join(before, "\n"), strings.Join(after, "\n")
}

func capEdit(before, after string) (string, string, bool) {
	truncated := false
	if len(before) > editTextCap {
		before = before[:editTextCap]
		truncated = true
	}
	if len(after) > editTextCap {
		after = after[:editTextCap]
		truncated = true
	}
	return before, after, truncated
}
