package privacy

import (
	"fmt"
	"regexp"
)

type redactionPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// redactionPatterns are compiled once at package init.
var redactionPatterns []redactionPattern

func init() {
	defs := []struct {
		name    string
		pattern string
	}{
		{"aws_access_key", `AKIA[0-9A-Z]{16}`},
		{"github_token", `gh[pousr]_[A-Za-z0-9_]{36,255}`},
		{"gitlab_token", `glpat-[A-Za-z0-9\-_]{20,}`},
		{"openai_key", `sk-[A-Za-z0-9]{20,}`},
		{"anthropic_key", `sk-ant-[A-Za-z0-9\-_]{20,}`},
		{"stripe_key", `[sr]k_(live|test)_[A-Za-z0-9]{20,}`},
		{"slack_token", `xox[baprs]-[A-Za-z0-9\-]+`},
		{"npm_token", `npm_[A-Za-z0-9]{36,}`},
		{"bearer_token", `(?i)Bearer\s+[A-Za-z0-9\-_.~+/]+=*`},
		{"basic_auth", `(?i)Basic\s+[A-Za-z0-9+/]+=*`},
		{"private_key_block", `(?s)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----.*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----`},
		{"connection_string", `[a-z]+://[^:]+:[^@]+@`},
		{"jwt", `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`},
		{"env_secret", `(?i)(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE_KEY)\s*=\s*[^\s"']{8,}`},
	}

	for _, d := range defs {
		redactionPatterns = append(redactionPatterns, redactionPattern{
			Name:    d.name,
			Pattern: regexp.MustCompile(d.pattern),
		})
	}
}

// Redact scrubs secret patterns from text. Returns the scrubbed text and
// a list of pattern names that matched.
func Redact(text string) (scrubbed string, matched []string) {
	if text == "" {
		return text, nil
	}

	seen := map[string]bool{}
	result := text

	for _, p := range redactionPatterns {
		func() {
			defer func() {
				if r := recover(); r != nil {
					result = fmt.Sprintf("[REDACTION_ERROR: %v]", r)
				}
			}()

			replaced := p.Pattern.ReplaceAllString(result, fmt.Sprintf("[REDACTED:%s]", p.Name))
			if replaced != result {
				result = replaced
				if !seen[p.Name] {
					seen[p.Name] = true
					matched = append(matched, p.Name)
				}
			}
		}()
	}

	return result, matched
}

// RedactFields applies Redact to each provided field value.
// It returns the scrubbed values (in the same order) and a deduplicated
// list of field names where at least one pattern matched.
func RedactFields(fields map[string]string) (map[string]string, []string) {
	result := make(map[string]string, len(fields))
	var redactedFieldNames []string

	for name, value := range fields {
		scrubbed, matched := Redact(value)
		result[name] = scrubbed
		if len(matched) > 0 {
			redactedFieldNames = append(redactedFieldNames, name)
		}
	}

	return result, redactedFieldNames
}
