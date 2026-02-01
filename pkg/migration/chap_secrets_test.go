package migration

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseChapSecretsIdentities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chap-secrets")
	content := "" +
		"# comment\n" +
		"alice * pass *\n" +
		"bob \"server\" \"secret\" *\n" +
		"alice * pass *\n"

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write chap-secrets: %v", err)
	}

	ids, err := ParseChapSecretsIdentities(path)
	if err != nil {
		t.Fatalf("ParseChapSecretsIdentities returned error: %v", err)
	}

	want := []string{"alice", "bob"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("expected %v, got %v", want, ids)
	}
}
