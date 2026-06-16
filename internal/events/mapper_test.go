package events

import "testing"

func TestMapToolToAction(t *testing.T) {
	tests := []struct {
		tool   string
		expect string
	}{
		{"Read", ActionFileRead},
		{"Grep", ActionFileRead},
		{"Glob", ActionFileRead},
		{"Write", ActionFileWrite},
		{"Edit", ActionFileWrite},
		{"MultiEdit", ActionFileWrite},
		{"Bash", ActionCommandExec},
		{"WebFetch", ActionNetworkReq},
		{"Task", ActionSubagentSpawn},
		{"Plan", ActionPlan},
		{"mcp__memory__create_entities", ActionMCPToolUse},
		{"mcp__github__create_pr", ActionMCPToolUse},
		{"Unknown", ActionUnknown},
		{"", ActionUnknown},
	}

	for _, tt := range tests {
		got := MapToolToAction(tt.tool)
		if got != tt.expect {
			t.Errorf("MapToolToAction(%q) = %q, want %q", tt.tool, got, tt.expect)
		}
	}
}

func TestParseMCPTool(t *testing.T) {
	tests := []struct {
		input  string
		server string
		tool   string
	}{
		{"mcp__memory__create_entities", "memory", "create_entities"},
		{"mcp__github__create_pull_request", "github", "create_pull_request"},
		{"mcp__linear__get_issue", "linear", "get_issue"},
		{"mcp__server", "", "mcp__server"}, // only 2 parts — not a valid MCP tool
		{"plain_tool", "", "plain_tool"},
	}

	for _, tt := range tests {
		server, tool := ParseMCPTool(tt.input)
		if server != tt.server || tool != tt.tool {
			t.Errorf("ParseMCPTool(%q) = (%q, %q), want (%q, %q)",
				tt.input, server, tool, tt.server, tt.tool)
		}
	}
}
