package privacy

import "testing"

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{
		".env",
		".env.local",
		".env.production",
		"config/server.key",
		"certs/tls.pem",
		"deploy.p12",
		"keystore.jks",
		"/home/dev/.ssh/id_rsa",
		"/home/dev/.ssh/id_ed25519.pub",
		"/home/dev/.ssh/known_hosts",
		"/home/dev/.aws/credentials",
		"/home/dev/.gcp/credentials.json",
		"/home/dev/.azure/config",
		"app_secret_key.txt",
		"db_password.conf",
		"api_credentials.json",
		"terraform.tfvars",
		"production.auto.tfvars",
		".npmrc",
		".pypirc",
		".git-credentials",
		".netrc",
		".docker/config.json",
	}

	for _, path := range sensitive {
		if !IsSensitivePath(path) {
			t.Errorf("expected %q to be sensitive", path)
		}
	}

	notSensitive := []string{
		"src/main.go",
		"README.md",
		"package.json",
		"go.mod",
		"internal/auth/middleware.go",
		"config/app.yaml",
		"scripts/deploy.sh",
		"",
	}

	for _, path := range notSensitive {
		if IsSensitivePath(path) {
			t.Errorf("expected %q NOT to be sensitive", path)
		}
	}
}
