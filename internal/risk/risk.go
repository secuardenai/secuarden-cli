package risk

import "strings"

type Assessment struct {
	Level   string   `json:"level"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons,omitempty"`
}

// Assess applies transparent, deterministic governance heuristics. It is not SAST.
func Assess(path string, sensitive bool) Assessment {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	score := 0
	reasons := []string{}
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}
	if sensitive {
		add(70, "sensitive path")
	}
	for _, item := range []struct {
		tokens []string
		points int
		reason string
	}{
		{[]string{"auth", "oauth", "login", "session", "permission", "rbac"}, 45, "identity or access control"},
		{[]string{"payment", "billing", "checkout", "invoice"}, 45, "payment or billing"},
		{[]string{"crypto", "secret", "token", "credential", "password", ".env"}, 55, "secret or cryptographic material"},
		{[]string{"migration", "schema", "terraform", "k8s", "deploy", "workflow"}, 30, "infrastructure or data schema"},
		{[]string{"test", "spec", "fixture", "docs/", ".md"}, -15, "test or documentation"},
	} {
		for _, token := range item.tokens {
			if strings.Contains(p, token) {
				add(item.points, item.reason)
				break
			}
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	level := "low"
	if score >= 70 {
		level = "critical"
	} else if score >= 45 {
		level = "high"
	} else if score >= 20 {
		level = "medium"
	}
	return Assessment{Level: level, Score: score, Reasons: reasons}
}
