package agent

import (
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
	"testing"
)

func TestLegacyHookRemovalPreservesIndependentObserver(t *testing.T) {
	fragment, err := observationcapture.HookDefinitions("/tmp/secuarden", "/tmp/observations")
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range fragment["hooks"].(map[string]interface{}) {
		entries := value.([]interface{})
		for _, entry := range entries {
			if isSecuardenEntry(entry) {
				t.Fatalf("legacy removal would remove observer %s", name)
			}
		}
	}
}
