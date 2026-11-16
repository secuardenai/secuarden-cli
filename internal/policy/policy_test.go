package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const source = "from flask_login import login_required\n\n@app.route('/private')\n@login_required\ndef private():\n    return 'hello'\n"

func activate(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cwd := t.TempDir()
	fixture, err := filepath.Abs("../../fixtures/policy/flask-security.json")
	if err != nil {
		t.Fatal(err)
	}
	n, skipped, err := Import(fixture)
	if err != nil || n != 1 || len(skipped) != 0 {
		t.Fatalf("import: %d %v %v", n, skipped, err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "app.py"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return cwd
}

func proposal(cwd, tool string, input any) []byte {
	data, _ := json.Marshal(map[string]any{"cwd": cwd, "tool_name": tool, "tool_input": input})
	return data
}

func TestEdits(t *testing.T) {
	cwd := activate(t)
	for _, tc := range []struct {
		name, after string
		deny        bool
	}{
		{"remove", strings.Replace(source, "@login_required\n", "", 1), true},
		{"comment", strings.Replace(source, "@login_required", "# @login_required", 1), true},
		{"arguments", strings.Replace(source, "@login_required", "@login_required(optional=True)", 1), true},
		{"route", strings.Replace(source, "/private", "/public", 1), true},
		{"detach", strings.Replace(source, "def private", "def other", 1), true},
		{"delete", "", true},
		{"syntax", "invalid python !", true},
		{"body", strings.Replace(source, "hello", "world", 1), false},
		{"comment only", source + "\n# safe comment\n", false},
		{"format", strings.Replace(source, "'/private'", "\"/private\"", 1), false},
		{"rebind", strings.Replace(source, "from flask_login", "from insecure", 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := Evaluate(proposal(cwd, "Write", map[string]any{"file_path": "app.py", "content": tc.after}))
			if (reason != "") != tc.deny {
				t.Fatalf("denied=%v reason=%s", tc.deny, reason)
			}
		})
	}
	for _, tool := range []string{"Bash", "exec_command", "shell_command", "mcp__writer"} {
		if Evaluate(proposal(cwd, tool, map[string]any{})) == "" {
			t.Fatalf("allowed %s", tool)
		}
	}
	if reason := Evaluate(proposal(cwd, "Read", map[string]any{"file_path": "app.py"})); reason != "" {
		t.Fatal(reason)
	}
	if reason := Evaluate(proposal(cwd, "Edit", map[string]any{"file_path": "app.py", "old_string": "@login_required\n", "new_string": ""})); reason == "" {
		t.Fatal("allowed removal")
	}
	if reason := Evaluate(proposal(cwd, "MultiEdit", map[string]any{"file_path": "app.py", "edits": []any{map[string]any{"old_string": "hello", "new_string": "world"}, map[string]any{"old_string": "@login_required\n", "new_string": ""}}})); reason == "" {
		t.Fatal("allowed multiedit removal")
	}
}

func TestCodexPatches(t *testing.T) {
	cwd := activate(t)
	for _, tc := range []struct {
		name, patch string
		deny        bool
	}{
		{"remove", "*** Update File: app.py\n@@\n-@login_required\n", true},
		{"body", "*** Update File: app.py\n@@\n-    return 'hello'\n+    return 'world'\n", false},
		{"delete", "*** Delete File: app.py\n", true},
		{"batch", "*** Add File: notes.txt\n+hello\n*** Update File: app.py\n@@\n-@login_required\n", true},
		{"fuzzy", "*** Update File: app.py\n@@\n- return 'hello'\n+ return 'world'\n", true},
		{"rename", "*** Update File: app.py\n*** Move to: other.py\n@@\n-    return 'hello'\n+    return 'world'\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			patch := "*** Begin Patch\n" + tc.patch + "*** End Patch"
			for _, input := range []any{patch, map[string]any{"command": patch}, map[string]any{"input": patch}, map[string]any{"patch": patch}} {
				reason := Evaluate(proposal(cwd, "apply_patch", input))
				if (reason != "") != tc.deny {
					t.Fatalf("denied=%v reason=%s", tc.deny, reason)
				}
			}
		})
	}
	data, _ := os.ReadFile(filepath.Join(cwd, "app.py"))
	if string(data) != source {
		t.Fatal("evaluation mutated source")
	}
}

func TestImportAndFailureModes(t *testing.T) {
	cwd := activate(t)
	policies, err := Load()
	if err != nil || len(policies) != 1 {
		t.Fatal(policies, err)
	}
	valid, _ := json.Marshal(policies[0])
	mixed := []byte(`{"version":"0.1","policies":[` + string(valid) + `,{"id":"bad","kind":"arbitrary"},` + string(valid) + `]}`)
	got, skipped, err := ParseImport(mixed)
	if err != nil || len(got) != 1 || len(skipped) != 2 {
		t.Fatal(got, skipped, err)
	}
	for _, bad := range []string{`{`, `{"version":"2","policies":[]}`, `{"version":"0.1","policies":[]} {}`} {
		if _, _, err := ParseImport([]byte(bad)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	input := filepath.Join(cwd, "policies.json")
	if err := os.WriteFile(input, mixed, 0600); err != nil {
		t.Fatal(err)
	}
	n, skipped, err := Import(input)
	if err != nil || n != 0 || len(skipped) != 3 {
		t.Fatal(n, skipped, err)
	}
	store, _ := StorePath()
	if err := os.WriteFile(store, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if Evaluate(proposal(cwd, "Read", nil)) == "" {
		t.Fatal("corrupt store allowed action")
	}
	if err := os.Remove(store); err != nil {
		t.Fatal(err)
	}
	if Evaluate([]byte("malformed")) != "" {
		t.Fatal("no policies should remain passive")
	}
}

func TestAliasesMultilineAndOrder(t *testing.T) {
	cwd := activate(t)
	before := "from flask_jwt_extended import jwt_required as guard\n@bp.get('/private')\n@guard(\n    fresh=True,\n)\ndef private():\n    return 'hello'\n"
	if err := os.WriteFile(filepath.Join(cwd, "app.py"), []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for _, after := range []string{strings.Replace(before, "fresh=True", "fresh=False", 1), strings.Replace(before, "@guard(\n    fresh=True,\n)\n", "", 1), strings.Replace(before, "@bp.get('/private')\n@guard(\n    fresh=True,\n)", "@guard(fresh=True)\n@bp.get('/private')", 1)} {
		if Evaluate(proposal(cwd, "Write", map[string]any{"file_path": "app.py", "content": after})) == "" {
			t.Fatal("allowed alias/multiline/order change")
		}
	}
}

func TestPythonSymlinkAndUnavailableParser(t *testing.T) {
	cwd := activate(t)
	if err := os.Rename(filepath.Join(cwd, "app.py"), filepath.Join(cwd, "source.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("source.txt", filepath.Join(cwd, "app.py")); err != nil {
		t.Fatal(err)
	}
	input := proposal(cwd, "Edit", map[string]any{"file_path": "app.py", "old_string": "@login_required\n", "new_string": ""})
	if Evaluate(input) == "" {
		t.Fatal("symlink bypassed Python enforcement")
	}
	t.Setenv("PATH", t.TempDir())
	input = proposal(cwd, "Edit", map[string]any{"file_path": "app.py", "old_string": "hello", "new_string": "world"})
	if Evaluate(input) == "" {
		t.Fatal("unavailable parser allowed edit")
	}
}

func TestDecoratorAliasesRespectScope(t *testing.T) {
	for _, tc := range []struct {
		name, before string
	}{
		{"unrelated function", "from flask_login import login_required as guard\n@app.route('/private')\n@guard\ndef private():\n    return 'hello'\n\ndef unrelated():\n    from unrelated_module import helper as guard\n"},
		{"unrelated class", "from flask_login import login_required as guard\nclass Unrelated:\n    from unrelated_module import helper as guard\n@app.route('/private')\n@guard\ndef private():\n    return 'hello'\n"},
		{"own body", "from flask_login import login_required as guard\n@app.route('/private')\n@guard\ndef private():\n    from unrelated_module import helper as guard\n    return 'hello'\n"},
		{"nested function", "def register():\n    from flask_login import login_required as guard\n    @app.route('/private')\n    @guard\n    def private():\n        return 'hello'\n    def unrelated():\n        from unrelated_module import helper as guard\n"},
		{"class decorator scope", "class Routes:\n    from flask_login import login_required as guard\n    @app.route('/private')\n    @guard\n    def private():\n        from unrelated_module import helper as guard\n        return 'hello'\n"},
		{"method skips class scope", "from flask_login import login_required as guard\nclass Routes:\n    from unrelated_module import helper as guard\n    def register(self):\n        @app.route('/private')\n        @guard\n        def private():\n            return 'hello'\n"},
		{"later import", "from flask_login import login_required as guard\n@app.route('/private')\n@guard\ndef private():\n    return 'hello'\nfrom unrelated_module import helper as guard\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := activate(t)
			if err := os.WriteFile(filepath.Join(cwd, "app.py"), []byte(tc.before), 0600); err != nil {
				t.Fatal(err)
			}
			for _, edit := range []struct {
				name, after string
				deny        bool
			}{
				{"remove decorator", strings.Replace(tc.before, "@guard", "# removed guard", 1), true},
				{"change protected import", strings.Replace(tc.before, "from flask_login", "from insecure", 1), true},
				{"body edit", strings.Replace(tc.before, "hello", "world", 1), false},
				{"unrelated import edit", strings.ReplaceAll(tc.before, "unrelated_module", "another_module"), false},
			} {
				t.Run(edit.name, func(t *testing.T) {
					reason := Evaluate(proposal(cwd, "Write", map[string]any{"file_path": "app.py", "content": edit.after}))
					if (reason != "") != edit.deny {
						t.Fatalf("denied=%v, want %v: %s", reason != "", edit.deny, reason)
					}
				})
			}
		})
	}
}
