// Package posture flags explicit security and privacy regressions in an agent edit.
// A path name is not evidence. An empty result means no detector fired.
package posture

import (
	"regexp"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/privacy"
)

const (
	KindControlRelaxed   = "control_relaxed"
	KindExposureWidened  = "exposure_widened"
	KindSecretIntroduced = "secret_introduced"
)

// Finding is one evidenced posture regression.
type Finding struct {
	Kind        string
	Explanation string
}

var (
	bypassPrompt = regexp.MustCompile(`(?i)(disable|remove|skip|bypass|weaken|turn off|comment out).{0,80}(login|auth|authori[sz]ation|permission|csrf|tls|certificate|check)`)
	decorators   = regexp.MustCompile(`(?m)^\s*@(login_required|fresh_login_required|roles_required|roles_accepted|jwt_required|auth_required)\b`)
	tlsOff       = regexp.MustCompile(`(?i)(verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false|SECURE_SSL_REDIRECT\s*=\s*False)`)
	csrfOff      = regexp.MustCompile(`(?i)(@csrf_exempt\b|CSRF_ENABLED\s*=\s*False|csrf\(\)\.exempt)`)
	corsWide     = regexp.MustCompile(`Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*`)
)

// Detect compares the edit that was proposed. Callers redact text before storage.
func Detect(prompt, before, after string) []Finding {
	if before == after {
		return nil
	}
	var found []Finding
	if removed(decorators, before, after) || added(tlsOff, before, after) || added(csrfOff, before, after) {
		explanation := "The edit relaxes an authentication, authorization, TLS, or CSRF control."
		if bypassPrompt.MatchString(prompt) {
			explanation = "The prompt asks to bypass a control, and the edit relaxes one."
		}
		found = append(found, Finding{Kind: KindControlRelaxed, Explanation: explanation})
	}
	if added(corsWide, before, after) {
		found = append(found, Finding{Kind: KindExposureWidened, Explanation: "The edit widens a cross-origin exposure to any origin."})
	}
	if secretIntroduced(before, after) {
		found = append(found, Finding{Kind: KindSecretIntroduced, Explanation: "The edit introduces a secret or credential pattern that was not in the replaced text."})
	}
	return found
}

func removed(pattern *regexp.Regexp, before, after string) bool {
	return pattern.MatchString(before) && !pattern.MatchString(after)
}

func added(pattern *regexp.Regexp, before, after string) bool {
	return pattern.MatchString(after) && !pattern.MatchString(before)
}

func secretIntroduced(before, after string) bool {
	_, previous := privacy.Redact(before)
	_, next := privacy.Redact(after)
	have := map[string]bool{}
	for _, name := range previous {
		have[name] = true
	}
	for _, name := range next {
		if !have[name] {
			return true
		}
	}
	return false
}

// Excerpt keeps a short redacted prompt for the finding.
func Excerpt(prompt string) string {
	prompt = strings.TrimSpace(prompt)
	scrubbed, _ := privacy.Redact(prompt)
	if len(scrubbed) > 240 {
		return scrubbed[:240]
	}
	return scrubbed
}
