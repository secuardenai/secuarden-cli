package events

import (
	"fmt"
	"strings"
)

// AffectedFile is content-free structural evidence extracted from a patch.
// Rename patches produce separate move_source and move_destination entries so
// privacy classification is applied to both paths.
type AffectedFile struct {
	Path        string `json:"path"`
	Operation   string `json:"operation"`
	IsSensitive bool   `json:"is_sensitive"`
}

// ParseApplyPatch extracts paths and line-count evidence from Codex's
// apply_patch grammar. Errors are deliberately generic so patch content can
// never be copied into logs or capture diagnostics.
func ParseApplyPatch(patch string) ([]AffectedFile, string, error) {
	lines := strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n")
	if len(lines) < 2 || lines[0] != "*** Begin Patch" {
		return nil, "", fmt.Errorf("unsupported apply_patch structure")
	}

	var files []AffectedFile
	current := -1
	bodyKind := ""
	bodyLines := 0
	bodyChanges := 0
	moved := false
	endOfFile := false
	ended := false
	added, removed := 0, 0
	finishSection := func() error {
		switch bodyKind {
		case "add":
			if bodyLines == 0 {
				return fmt.Errorf("unsupported apply_patch structure")
			}
		case "update":
			if bodyChanges == 0 && !moved {
				return fmt.Errorf("unsupported apply_patch structure")
			}
		case "delete":
			if bodyLines != 0 {
				return fmt.Errorf("unsupported apply_patch structure")
			}
		default:
			return fmt.Errorf("unsupported apply_patch structure")
		}
		return nil
	}
	startSection := func(kind string) {
		bodyKind = kind
		bodyLines = 0
		bodyChanges = 0
		moved = false
		endOfFile = false
	}
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		switch {
		case line == "*** End Patch":
			if current < 0 || len(files) == 0 || finishSection() != nil {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			for _, trailing := range lines[i+1:] {
				if trailing != "" {
					return nil, "", fmt.Errorf("unsupported apply_patch structure")
				}
			}
			ended = true
			i = len(lines)
		case strings.HasPrefix(line, "*** Add File: "):
			if current >= 0 && finishSection() != nil {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			path, ok := patchPath(line, "*** Add File: ")
			if !ok {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			files = append(files, AffectedFile{Path: path, Operation: "add"})
			current = len(files) - 1
			startSection("add")
		case strings.HasPrefix(line, "*** Delete File: "):
			if current >= 0 && finishSection() != nil {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			path, ok := patchPath(line, "*** Delete File: ")
			if !ok {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			files = append(files, AffectedFile{Path: path, Operation: "delete"})
			current = len(files) - 1
			startSection("delete")
		case strings.HasPrefix(line, "*** Update File: "):
			if current >= 0 && finishSection() != nil {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			path, ok := patchPath(line, "*** Update File: ")
			if !ok {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			files = append(files, AffectedFile{Path: path, Operation: "update"})
			current = len(files) - 1
			startSection("update")
		case strings.HasPrefix(line, "*** Move to: "):
			path, ok := patchPath(line, "*** Move to: ")
			if !ok || current < 0 || bodyKind != "update" || moved || bodyLines != 0 {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			files[current].Operation = "move_source"
			files = append(files, AffectedFile{Path: path, Operation: "move_destination"})
			current = len(files) - 1
			moved = true
		case strings.HasPrefix(line, "*** ") && line != "*** End of File":
			return nil, "", fmt.Errorf("unsupported apply_patch structure")
		default:
			if current < 0 {
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
			switch bodyKind {
			case "add":
				if !strings.HasPrefix(line, "+") {
					return nil, "", fmt.Errorf("unsupported apply_patch structure")
				}
				bodyLines++
				bodyChanges++
				added++
			case "update":
				if endOfFile {
					return nil, "", fmt.Errorf("unsupported apply_patch structure")
				}
				switch {
				case line == "*** End of File":
					endOfFile = true
				case line == "@@" || strings.HasPrefix(line, "@@ "):
				case strings.HasPrefix(line, "+"):
					added++
					bodyChanges++
				case strings.HasPrefix(line, "-"):
					removed++
					bodyChanges++
				case strings.HasPrefix(line, " "):
				default:
					return nil, "", fmt.Errorf("unsupported apply_patch structure")
				}
				bodyLines++
			case "delete":
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			default:
				return nil, "", fmt.Errorf("unsupported apply_patch structure")
			}
		}
	}
	if !ended {
		return nil, "", fmt.Errorf("unsupported apply_patch structure")
	}
	return files, fmt.Sprintf("+%d/-%d", added, removed), nil
}

func patchPath(line, prefix string) (string, bool) {
	path := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	return path, path != "" && !strings.ContainsRune(path, '\x00')
}
