package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDisarmRollback_RemovesMarker(t *testing.T) {
	dir := t.TempDir()
	id := "123"
	if err := os.WriteFile(filepath.Join(dir, id), []byte("x"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	found, err := disarmRollback(dir, id)
	if err != nil {
		t.Fatalf("disarmRollback error: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true")
	}
	if _, err := os.Stat(filepath.Join(dir, id)); !os.IsNotExist(err) {
		t.Fatalf("expected marker to be removed, stat err=%v", err)
	}
}

func TestDisarmRollback_MissingMarker(t *testing.T) {
	dir := t.TempDir()
	found, err := disarmRollback(dir, "missing")
	if err != nil {
		t.Fatalf("disarmRollback error: %v", err)
	}
	if found {
		t.Fatalf("expected found=false")
	}
}

