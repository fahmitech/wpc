package migration

import "testing"

func TestSafePeerName(t *testing.T) {
	got, err := SafePeerName("bob smith")
	if err != nil {
		t.Fatalf("SafePeerName returned error: %v", err)
	}
	if got != "peer_bob_smith" {
		t.Fatalf("expected peer_bob_smith, got %s", got)
	}
}
