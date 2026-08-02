package uploadschema_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const envelopeSchemaURL = "https://schema.secuarden.ai/upload/1.0/session-envelope.schema.json"

type offlineLoader map[string]any

func (l offlineLoader) Load(url string) (any, error) {
	if doc, ok := l[url]; ok {
		return doc, nil
	}
	return nil, fmt.Errorf("schema reference %q was not preloaded; network resolution is disabled", url)
}

func TestSessionEnvelopeFixtureMatchesSchemaOffline(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate schema test")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../.."))

	compiler := jsonschema.NewCompiler()
	resources := map[string]string{
		envelopeSchemaURL: filepath.Join(repoRoot, "schema/upload/v1/session-envelope.schema.json"),
		"https://schema.secuarden.ai/stage1/2.0/event.schema.json": filepath.Join(repoRoot, "schema/stage1/v2/event.schema.json"),
		"https://schema.secuarden.ai/v1/event.schema.json":         filepath.Join(repoRoot, "schema/secuarden-event.schema.json"),
	}
	loader := offlineLoader{}
	for url, path := range resources {
		loader[url] = readJSON(t, path)
	}
	compiler.UseLoader(loader)

	schema, err := compiler.Compile(envelopeSchemaURL)
	if err != nil {
		t.Fatalf("compile schema and resolve local references: %v", err)
	}
	fixture := readJSON(t, filepath.Join(repoRoot, "fixtures/upload/v1/session-envelope.json"))
	if err := schema.Validate(fixture); err != nil {
		t.Fatalf("fixture violates session envelope schema: %v", err)
	}
}

func readJSON(t *testing.T, path string) any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc
}
