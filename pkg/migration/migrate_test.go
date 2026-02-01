package migration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fahmitech/wpc/pkg/compiler"
	"github.com/fahmitech/wpc/pkg/types"
)

func TestRunMigrateOpenVPN(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.txt")
	content := "" +
		"V\t260101000000Z\t\t01\tunknown\t/CN=alice\n" +
		"V\t260101000000Z\t\t02\tunknown\t/CN=bob smith\n"
	if err := os.WriteFile(indexPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write index.txt: %v", err)
	}

	exportDir := filepath.Join(dir, "export")
	err := RunMigrate(MigrateRequest{
		Source:     "openvpn",
		Config:     indexPath,
		CIDR:       "10.50.0.0/24",
		Endpoint:   "1.2.3.4",
		ListenPort: 51820,
		OutputDir:  exportDir,
		Force:      false,
	})
	if err != nil {
		t.Fatalf("RunMigrate returned error: %v", err)
	}

	wg0Bytes, err := os.ReadFile(filepath.Join(exportDir, "wg0.conf"))
	if err != nil {
		t.Fatalf("read wg0.conf: %v", err)
	}
	wg0 := string(wg0Bytes)
	if !strings.Contains(wg0, "[Interface]") || !strings.Contains(wg0, "[Peer]") {
		t.Fatalf("wg0.conf does not look like a WireGuard config:\n%s", wg0)
	}
	if !strings.Contains(wg0, "AllowedIPs = 10.50.0.2/32") || !strings.Contains(wg0, "AllowedIPs = 10.50.0.3/32") {
		t.Fatalf("wg0.conf missing expected AllowedIPs assignments:\n%s", wg0)
	}

	policyBytes, err := os.ReadFile(filepath.Join(exportDir, "policy.json"))
	if err != nil {
		t.Fatalf("read policy.json: %v", err)
	}
	var policy types.Policy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		t.Fatalf("unmarshal policy.json: %v", err)
	}
	if err := compiler.ParseAndValidate(&policy); err != nil {
		t.Fatalf("generated policy did not validate: %v", err)
	}

	if got := policy.Definitions["peer_alice"]; len(got) != 1 || got[0] != "10.50.0.2" {
		t.Fatalf("peer_alice definition unexpected: %v", got)
	}
	if got := policy.Definitions["peer_bob_smith"]; len(got) != 1 || got[0] != "10.50.0.3" {
		t.Fatalf("peer_bob_smith definition unexpected: %v", got)
	}

	if _, err := os.Stat(filepath.Join(exportDir, "clients", "peer_alice.conf")); err != nil {
		t.Fatalf("missing peer_alice.conf: %v", err)
	}
	if _, err := os.Stat(filepath.Join(exportDir, "clients", "peer_bob_smith.conf")); err != nil {
		t.Fatalf("missing peer_bob_smith.conf: %v", err)
	}
}

func TestRunMigrateEndpointPortOverridesListenPort(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.txt")
	content := "" +
		"V\t260101000000Z\t\t01\tunknown\t/CN=alice\n"
	if err := os.WriteFile(indexPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write index.txt: %v", err)
	}

	exportDir := filepath.Join(dir, "export")
	err := RunMigrate(MigrateRequest{
		Source:     "openvpn",
		Config:     indexPath,
		CIDR:       "10.50.0.0/24",
		Endpoint:   "1.2.3.4:9999",
		ListenPort: 51820,
		OutputDir:  exportDir,
		Force:      false,
	})
	if err != nil {
		t.Fatalf("RunMigrate returned error: %v", err)
	}

	wg0Bytes, err := os.ReadFile(filepath.Join(exportDir, "wg0.conf"))
	if err != nil {
		t.Fatalf("read wg0.conf: %v", err)
	}
	wg0 := string(wg0Bytes)
	if !strings.Contains(wg0, "ListenPort = 9999") {
		t.Fatalf("expected server listen port override to 9999:\n%s", wg0)
	}

	clientBytes, err := os.ReadFile(filepath.Join(exportDir, "clients", "peer_alice.conf"))
	if err != nil {
		t.Fatalf("read client conf: %v", err)
	}
	clientConf := string(clientBytes)
	if !strings.Contains(clientConf, "Endpoint = 1.2.3.4:9999") {
		t.Fatalf("expected client endpoint to include 9999:\n%s", clientConf)
	}
}

func TestRunMigrateForceCleansStaleClients(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.txt")
	exportDir := filepath.Join(dir, "export")

	content1 := "" +
		"V\t260101000000Z\t\t01\tunknown\t/CN=alice\n" +
		"V\t260101000000Z\t\t02\tunknown\t/CN=bob\n"
	if err := os.WriteFile(indexPath, []byte(content1), 0o600); err != nil {
		t.Fatalf("write index.txt: %v", err)
	}
	if err := RunMigrate(MigrateRequest{
		Source:     "openvpn",
		Config:     indexPath,
		CIDR:       "10.50.0.0/24",
		Endpoint:   "1.2.3.4",
		ListenPort: 51820,
		OutputDir:  exportDir,
		Force:      false,
	}); err != nil {
		t.Fatalf("first RunMigrate returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(exportDir, "clients", "peer_bob.conf")); err != nil {
		t.Fatalf("expected peer_bob.conf to exist after first run: %v", err)
	}

	content2 := "" +
		"V\t260101000000Z\t\t01\tunknown\t/CN=alice\n"
	if err := os.WriteFile(indexPath, []byte(content2), 0o600); err != nil {
		t.Fatalf("rewrite index.txt: %v", err)
	}
	if err := RunMigrate(MigrateRequest{
		Source:     "openvpn",
		Config:     indexPath,
		CIDR:       "10.50.0.0/24",
		Endpoint:   "1.2.3.4",
		ListenPort: 51820,
		OutputDir:  exportDir,
		Force:      true,
	}); err != nil {
		t.Fatalf("second RunMigrate returned error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(exportDir, "clients", "peer_bob.conf")); err == nil {
		t.Fatalf("expected stale peer_bob.conf to be removed on --force")
	}
}
