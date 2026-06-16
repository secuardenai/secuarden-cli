package events

import (
	"encoding/json"
	"os"
	"testing"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := "../../test/fixtures/" + name
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return data
}

func TestParseHookInput_Bash(t *testing.T) {
	data := loadFixture(t, "pretooluse_bash.json")
	raw, err := ParseHookInput(data)
	if err != nil {
		t.Fatalf("ParseHookInput: %v", err)
	}
	if raw.ToolName != "Bash" {
		t.Errorf("expected tool_name=Bash, got %q", raw.ToolName)
	}
	if ExtractCommand(raw.ToolInput) != "npm test" {
		t.Errorf("expected command=npm test, got %q", ExtractCommand(raw.ToolInput))
	}
}

func TestParseHookInput_Edit(t *testing.T) {
	data := loadFixture(t, "pretooluse_edit.json")
	raw, err := ParseHookInput(data)
	if err != nil {
		t.Fatalf("ParseHookInput: %v", err)
	}
	if raw.ToolName != "Edit" {
		t.Errorf("expected tool_name=Edit, got %q", raw.ToolName)
	}
	if ExtractFilePath(raw.ToolInput) != "src/auth/middleware.ts" {
		t.Errorf("expected file_path=src/auth/middleware.ts, got %q", ExtractFilePath(raw.ToolInput))
	}
}

func TestParseHookInput_MCP(t *testing.T) {
	data := loadFixture(t, "pretooluse_mcp.json")
	raw, err := ParseHookInput(data)
	if err != nil {
		t.Fatalf("ParseHookInput: %v", err)
	}
	if MapToolToAction(raw.ToolName) != ActionMCPToolUse {
		t.Errorf("expected mcp_tool_use action, got %q", MapToolToAction(raw.ToolName))
	}
	server, tool := ParseMCPTool(raw.ToolName)
	if server != "memory" || tool != "create_entities" {
		t.Errorf("ParseMCPTool: got (%q, %q)", server, tool)
	}
}

func TestParseHookInput_PostToolUseBash(t *testing.T) {
	data := loadFixture(t, "posttooluse_bash.json")
	raw, err := ParseHookInput(data)
	if err != nil {
		t.Fatalf("ParseHookInput: %v", err)
	}
	exitCode := ExtractExitCode(raw.ToolResponse)
	if exitCode == nil || *exitCode != 0 {
		t.Errorf("expected exit_code=0, got %v", exitCode)
	}
	preview := ExtractOutputPreview(raw.ToolResponse)
	if preview == "" {
		t.Error("expected non-empty output preview")
	}
	status := ExtractResultStatus(raw.ToolResponse)
	if status != ResultSuccess {
		t.Errorf("expected success, got %q", status)
	}
}

func TestParseHookInput_SessionStart(t *testing.T) {
	data := loadFixture(t, "sessionstart.json")
	raw, err := ParseHookInput(data)
	if err != nil {
		t.Fatalf("ParseHookInput: %v", err)
	}
	if raw.CWD != "/Users/dev/myproject" {
		t.Errorf("expected cwd=/Users/dev/myproject, got %q", raw.CWD)
	}
}

func TestParseHookInput_Invalid(t *testing.T) {
	_, err := ParseHookInput([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseHookInput_Empty(t *testing.T) {
	_, err := ParseHookInput([]byte("{}"))
	if err != nil {
		t.Errorf("unexpected error for empty object: %v", err)
	}
}

func TestExtractFilePath_MultipleKeys(t *testing.T) {
	tests := []struct {
		input  map[string]interface{}
		expect string
	}{
		{map[string]interface{}{"file_path": "foo.go"}, "foo.go"},
		{map[string]interface{}{"path": "bar.go"}, "bar.go"},
		{map[string]interface{}{"old_path": "baz.go"}, "baz.go"},
		{map[string]interface{}{}, ""},
	}
	for _, tt := range tests {
		got := ExtractFilePath(tt.input)
		if got != tt.expect {
			b, _ := json.Marshal(tt.input)
			t.Errorf("ExtractFilePath(%s) = %q, want %q", b, got, tt.expect)
		}
	}
}
