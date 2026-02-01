package migration

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseOpenVPNIndexTxt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.txt")
	content := "" +
		"V\t260101000000Z\t\t01\tunknown\t/CN=alice\n" +
		"R\t260101000000Z\t\t02\tunknown\t/CN=revoked\n" +
		"V\t260101000000Z\t\t03\tunknown\t/CN=bob smith\n" +
		"V\t260101000000Z\t\t04\tunknown\t/CN=alice\n"

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write index.txt: %v", err)
	}

	ids, err := ParseOpenVPNIdentities(path)
	if err != nil {
		t.Fatalf("ParseOpenVPNIdentities returned error: %v", err)
	}

	want := []string{"alice", "bob smith"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("expected %v, got %v", want, ids)
	}
}
