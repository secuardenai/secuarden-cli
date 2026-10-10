package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// CodexToolResult is the privacy-neutral normalization of Codex's arbitrary
// PostToolUse tool_response value. Fields contains only recognized content and
// structural status values understood by the shared extraction helpers.
type CodexToolResult struct {
	Fields       map[string]interface{}
	ResultStatus string
	Supported    bool
}

// NormalizeCodexToolResponse interprets only explicit, supported outcome
// signals. Content without an outcome signal is retained for privacy handling
// but remains unknown; text is never searched for failure words.
func NormalizeCodexToolResponse(raw json.RawMessage, toolName string) (CodexToolResult, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return unknownCodexResult(nil), nil
	}
	if len(trimmed) > 1*1024*1024 {
		return unknownCodexResult(nil), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return CodexToolResult{}, fmt.Errorf("invalid Codex tool_response JSON")
	}
	return normalizeCodexResultValue(value, toolName), nil
}

func normalizeCodexResultValue(value interface{}, toolName string) CodexToolResult {
	switch typed := value.(type) {
	case map[string]interface{}:
		return normalizeCodexResultObject(typed, toolName)
	case []interface{}:
		return normalizeCodexResultArray(typed, toolName)
	case string:
		return unknownCodexResult(map[string]interface{}{"content": typed})
	case json.Number, bool:
		return unknownCodexResult(map[string]interface{}{"content": fmt.Sprint(typed)})
	default:
		return unknownCodexResult(nil)
	}
}

func normalizeCodexResultObject(object map[string]interface{}, toolName string) CodexToolResult {
	fields := map[string]interface{}{}
	if text, ok := object["text"].(string); ok && object["type"] == "text" {
		fields["content"] = text
	}
	if code, ok := codexExitCode(object); ok {
		fields["exit_code"] = code
	}
	if output := codexObjectOutput(object); output != "" {
		fields["content"] = output
	}

	failure, success := false, false
	if code, ok := codexExitCode(object); ok {
		if code == 0 {
			success = true
		} else {
			failure = true
		}
	}
	if errorValue, ok := object["error"]; ok && explicitCodexError(errorValue) {
		failure = true
		if _, present := fields["content"]; !present {
			if message := codexErrorMessage(errorValue); message != "" {
				fields["content"] = message
			}
		}
	}
	if strings.HasPrefix(toolName, "mcp__") {
		if isError, ok := object["isError"].(bool); ok {
			if isError {
				failure = true
			} else {
				success = true
			}
		}
	}
	for _, key := range []string{"success", "ok"} {
		if flag, ok := object[key].(bool); ok {
			if flag {
				success = true
			} else {
				failure = true
			}
		}
	}
	for _, key := range []string{"status", "result_status"} {
		status, ok := object[key].(string)
		if !ok {
			continue
		}
		switch strings.ToLower(status) {
		case "success", "completed", "ok":
			success = true
		case "error", "failed", "failure":
			failure = true
		}
	}
	if failure {
		return CodexToolResult{Fields: fields, ResultStatus: ResultError, Supported: true}
	}
	if success {
		return CodexToolResult{Fields: fields, ResultStatus: ResultSuccess, Supported: true}
	}
	return unknownCodexResult(fields)
}

func normalizeCodexResultArray(values []interface{}, toolName string) CodexToolResult {
	fields := map[string]interface{}{}
	parts := make([]string, 0, len(values))
	allSupported := len(values) > 0
	anySupported := false
	for _, value := range values {
		result := normalizeCodexResultValue(value, toolName)
		if content, ok := result.Fields["content"].(string); ok && content != "" {
			parts = append(parts, content)
		}
		if result.ResultStatus == ResultError {
			if len(parts) > 0 {
				fields["content"] = strings.Join(parts, "\n")
			}
			return CodexToolResult{Fields: fields, ResultStatus: ResultError, Supported: true}
		}
		if result.Supported {
			anySupported = true
		} else {
			allSupported = false
		}
	}
	if len(parts) > 0 {
		fields["content"] = strings.Join(parts, "\n")
	}
	if anySupported && allSupported {
		return CodexToolResult{Fields: fields, ResultStatus: ResultSuccess, Supported: true}
	}
	return unknownCodexResult(fields)
}

func unknownCodexResult(fields map[string]interface{}) CodexToolResult {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	return CodexToolResult{Fields: fields, ResultStatus: ResultUnknown, Supported: false}
}

func codexExitCode(object map[string]interface{}) (int, bool) {
	for _, key := range []string{"exit_code", "exitCode"} {
		value, ok := object[key]
		if !ok {
			continue
		}
		switch number := value.(type) {
		case json.Number:
			parsed, err := number.Int64()
			if err == nil && int64(int(parsed)) == parsed {
				return int(parsed), true
			}
		case float64:
			parsed := int(number)
			if float64(parsed) == number {
				return parsed, true
			}
		case int:
			return number, true
		}
	}
	return 0, false
}

func codexObjectOutput(object map[string]interface{}) string {
	for _, key := range []string{"output", "stdout", "content"} {
		if value, ok := object[key]; ok {
			if output := codexContentText(value); output != "" {
				return output
			}
		}
	}
	return ""
}

func codexContentText(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []interface{}:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			switch block := item.(type) {
			case string:
				parts = append(parts, block)
			case map[string]interface{}:
				if text, ok := block["text"].(string); ok {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func explicitCodexError(value interface{}) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case map[string]interface{}:
		return len(typed) > 0
	default:
		return true
	}
}

func codexErrorMessage(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]interface{}:
		if message, ok := typed["message"].(string); ok {
			return message
		}
	}
	return ""
}
