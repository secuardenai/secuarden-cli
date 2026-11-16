package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

// Reconstruct exact-match patches in memory. Ambiguous/fuzzy patches are denied,
// rather than making assumptions different from the agent's patch implementation.
func checkPatch(ctx context.Context, cwd, patch string, policies []Policy) error {
	if _, _, err := events.ParseApplyPatch(patch); err != nil {
		return fmt.Errorf("unsupported patch structure")
	}
	lines := strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n")
	seen := map[string]bool{}
	for i := 1; i < len(lines) && lines[i] != "*** End Patch"; {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("policy evaluation deadline exceeded")
		}
		header := lines[i]
		i++
		kind, path, ok := strings.Cut(strings.TrimPrefix(header, "*** "), ": ")
		if !ok {
			return fmt.Errorf("invalid patch header")
		}
		before, absolute, err := readSource(cwd, path)
		if err != nil {
			return fmt.Errorf("cannot read patch target")
		}
		if seen[absolute] {
			return fmt.Errorf("repeated patch target is unsupported")
		}
		seen[absolute] = true
		end := i
		for end < len(lines) && !strings.HasPrefix(lines[end], "*** Add File: ") && !strings.HasPrefix(lines[end], "*** Update File: ") && !strings.HasPrefix(lines[end], "*** Delete File: ") && lines[end] != "*** End Patch" {
			end++
		}
		after := before
		switch kind {
		case "Add File":
			if before != "" {
				return fmt.Errorf("add patch would overwrite an existing file")
			}
			var added []string
			for _, line := range lines[i:end] {
				if !strings.HasPrefix(line, "+") {
					return fmt.Errorf("invalid added line")
				}
				added = append(added, line[1:])
			}
			after = strings.Join(added, "\n") + "\n"
		case "Delete File":
			after = ""
		case "Update File":
			if i < end && strings.HasPrefix(lines[i], "*** Move to: ") {
				return fmt.Errorf("rename patches are not supported while decorator enforcement is active")
			}
			// Require complete unique line sequences, preserving existing newline state.
			cursor := 0
			for i < end {
				if err := ctx.Err(); err != nil {
					return fmt.Errorf("policy evaluation deadline exceeded")
				}
				if strings.HasPrefix(lines[i], "@@") {
					i++
				}
				var oldLines, newLines []string
				for i < end && !strings.HasPrefix(lines[i], "@@") {
					line := lines[i]
					i++
					if line == "*** End of File" {
						continue
					}
					if len(line) == 0 {
						return fmt.Errorf("unsupported empty patch line")
					}
					switch line[0] {
					case ' ':
						oldLines = append(oldLines, line[1:])
						newLines = append(newLines, line[1:])
					case '-':
						oldLines = append(oldLines, line[1:])
					case '+':
						newLines = append(newLines, line[1:])
					default:
						return fmt.Errorf("unsupported patch line")
					}
				}
				if len(oldLines) == 0 {
					return fmt.Errorf("patch insertion needs exact context")
				}
				old := strings.Join(oldLines, "\n")
				replacement := strings.Join(newLines, "\n")
				matches := []int{}
				start := cursor
				for start <= len(after) {
					index := strings.Index(after[start:], old)
					if index < 0 {
						break
					}
					index += start
					stop := index + len(old)
					if (index == 0 || after[index-1] == '\n') && (stop == len(after) || after[stop] == '\n') {
						matches = append(matches, index)
						if len(matches) > 1 {
							return fmt.Errorf("patch context is ambiguous; use an exact Edit")
						}
					}
					start = index + 1
				}
				if len(matches) != 1 {
					return fmt.Errorf("patch context is missing or ambiguous; use an exact Edit")
				}
				index := matches[0]
				stop := index + len(old)
				if len(newLines) == 0 && stop < len(after) && after[stop] == '\n' {
					stop++
				}
				after = after[:index] + replacement + after[stop:]
				cursor = index + len(replacement)
			}
		default:
			return fmt.Errorf("unsupported patch operation")
		}
		if err := checkFile(ctx, path, absolute, before, after, policies); err != nil {
			return err
		}
		i = end
	}
	return nil
}
