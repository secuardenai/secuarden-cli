package posture

import (
	"strings"
	"testing"
)

func TestDetectLoginBypassAndHarmlessRename(t *testing.T) {
	before := "@app.route('/private')\n@login_required\ndef private():\n    return 'ok'\n"
	after := "@app.route('/private')\ndef private():\n    return 'ok'\n"
	found := Detect("disable the login check so the demo works", before, after)
	if len(found) != 1 || found[0].Kind != KindControlRelaxed {
		t.Fatalf("findings = %#v", found)
	}
	if !strings.Contains(found[0].Explanation, "prompt asks") {
		t.Fatalf("explanation = %s", found[0].Explanation)
	}

	renamedBefore := "def authorize_request(user):\n    return user.allowed\n"
	renamedAfter := "def allow_request(user):\n    return user.allowed\n"
	if got := Detect("rename the helper", renamedBefore, renamedAfter); len(got) != 0 {
		t.Fatalf("harmless rename flagged: %#v", got)
	}
	if got := Detect("disable the login check so the demo works", renamedBefore, renamedAfter); len(got) != 0 {
		t.Fatalf("prompt without a matching edit flagged: %#v", got)
	}
}

func TestDetectSecretAndExposure(t *testing.T) {
	secret := Detect("", "token = ''\n", "token = 'sk-abcdefghijklmnopqrstuvwxyz123456'\n")
	if len(secret) != 1 || secret[0].Kind != KindSecretIntroduced {
		t.Fatalf("secret findings = %#v", secret)
	}
	exposure := Detect("", "origin = 'app.example'\n", "origin = Access-Control-Allow-Origin: *\n")
	if len(exposure) != 1 || exposure[0].Kind != KindExposureWidened {
		t.Fatalf("exposure findings = %#v", exposure)
	}
}
