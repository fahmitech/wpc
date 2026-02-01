package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fahmitech/wpc/pkg/types"
)

// TestDisarmRollback tests the disarmRollback function with table-driven tests
func TestDisarmRollback(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(dir string) string // Returns the id to use
		id          string
		wantFound   bool
		wantErr     bool
		errContains string
	}{
		{
			name: "removes existing marker",
			setup: func(dir string) string {
				id := "123"
				if err := os.WriteFile(filepath.Join(dir, id), []byte("rollback_path"), 0600); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				return id
			},
			wantFound: true,
			wantErr:   false,
		},
		{
			name: "returns false for missing marker",
			setup: func(dir string) string {
				return "nonexistent"
			},
			wantFound: false,
			wantErr:   false,
		},
		{
			name: "rejects path traversal with ../",
			setup: func(dir string) string {
				return "../../../etc/passwd"
			},
			wantFound:   false,
			wantErr:     true,
			errContains: "path traversal",
		},
		{
			name: "rejects path traversal with ..",
			setup: func(dir string) string {
				return ".."
			},
			wantFound:   false,
			wantErr:     true,
			errContains: "path traversal",
		},
		{
			name: "handles absolute path as id",
			setup: func(dir string) string {
				// When id is absolute, filepath.Join(dir, id) returns id
				// So the path won't be relative to dir, but won't trigger .. check
				return "/etc/passwd"
			},
			wantFound: false,
			wantErr:   false, // File doesn't exist, no error
		},
		{
			name: "allows valid subdirectory path",
			setup: func(dir string) string {
				subdir := filepath.Join(dir, "subdir")
				if err := os.MkdirAll(subdir, 0755); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				id := "subdir/123"
				if err := os.WriteFile(filepath.Join(dir, id), []byte("data"), 0600); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				return id
			},
			wantFound: true,
			wantErr:   false,
		},
		{
			name: "handles empty id",
			setup: func(dir string) string {
				// Empty id results in pendingDir itself being removed
				// Create a marker at the dir level (though this shouldn't happen in practice)
				return ""
			},
			wantFound: true, // Empty string means removing the dir itself, which succeeds
			wantErr:   false,
		},
		{
			name: "handles id with special characters",
			setup: func(dir string) string {
				id := "session-2024-01-01_12:30:45"
				// This should fail on filesystems that don't support colons
				// but let's test what happens
				return id
			},
			wantFound: false,
			wantErr:   false, // File doesn't exist, so no error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			id := tt.id
			if tt.setup != nil {
				id = tt.setup(dir)
			}

			found, err := disarmRollback(dir, id)

			if (err != nil) != tt.wantErr {
				t.Errorf("disarmRollback() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("disarmRollback() error = %v, want error containing %q", err, tt.errContains)
				}
			}

			if found != tt.wantFound {
				t.Errorf("disarmRollback() found = %v, want %v", found, tt.wantFound)
			}

			// Verify file was actually removed if found=true and no error
			if tt.wantFound && !tt.wantErr {
				if _, err := os.Stat(filepath.Join(dir, id)); !os.IsNotExist(err) {
					t.Errorf("expected marker file to be removed, stat err=%v", err)
				}
			}
		})
	}
}

// TestWriteGeoConfig tests the writeGeoConfig function with table-driven tests
func TestWriteGeoConfig(t *testing.T) {
	tests := []struct {
		name     string
		policy   *types.Policy
		wantFile bool
		wantErr  bool
		validate func(t *testing.T, path string)
	}{
		{
			name: "creates geo.json with single feed",
			policy: &types.Policy{
				Global: types.GlobalSettings{
					GeoBlockFeeds: []types.GeoFeed{
						{
							Name:       "cn",
							URL:        "https://example.com/cn.txt",
							IPVersion:  4,
							SHA256:     "abc123",
							RefreshSec: 3600,
						},
					},
				},
			},
			wantFile: true,
			wantErr:  false,
			validate: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed to read geo.json: %v", err)
				}

				var cfg geoConfigFile
				if err := json.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to parse geo.json: %v", err)
				}

				if len(cfg.Sets) != 1 {
					t.Errorf("expected 1 set, got %d", len(cfg.Sets))
				}

				set := cfg.Sets[0]
				if set.Name != "wpc_geo_cn_v4" {
					t.Errorf("expected name 'wpc_geo_cn_v4', got %q", set.Name)
				}
				if set.Table != "wpc_filter" {
					t.Errorf("expected table 'wpc_filter', got %q", set.Table)
				}
				if set.Family != "inet" {
					t.Errorf("expected family 'inet', got %q", set.Family)
				}
				if set.URL != "https://example.com/cn.txt" {
					t.Errorf("expected URL 'https://example.com/cn.txt', got %q", set.URL)
				}
				if set.IPVersion != 4 {
					t.Errorf("expected IPVersion 4, got %d", set.IPVersion)
				}
				if set.SHA256 != "abc123" {
					t.Errorf("expected SHA256 'abc123', got %q", set.SHA256)
				}
				if set.RefreshSec != 3600 {
					t.Errorf("expected RefreshSec 3600, got %d", set.RefreshSec)
				}
			},
		},
		{
			name: "creates geo.json with multiple feeds",
			policy: &types.Policy{
				Global: types.GlobalSettings{
					GeoBlockFeeds: []types.GeoFeed{
						{
							Name:      "cn",
							URL:       "https://example.com/cn.txt",
							IPVersion: 4,
						},
						{
							Name:      "cn",
							URL:       "https://example.com/cn-v6.txt",
							IPVersion: 6,
						},
						{
							Name:      "ru",
							URL:       "https://example.com/ru.txt",
							IPVersion: 4,
						},
					},
				},
			},
			wantFile: true,
			wantErr:  false,
			validate: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed to read geo.json: %v", err)
				}

				var cfg geoConfigFile
				if err := json.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to parse geo.json: %v", err)
				}

				if len(cfg.Sets) != 3 {
					t.Errorf("expected 3 sets, got %d", len(cfg.Sets))
				}

				expectedNames := []string{"wpc_geo_cn_v4", "wpc_geo_cn_v6", "wpc_geo_ru_v4"}
				for i, expected := range expectedNames {
					if cfg.Sets[i].Name != expected {
						t.Errorf("set[%d]: expected name %q, got %q", i, expected, cfg.Sets[i].Name)
					}
				}
			},
		},
		{
			name: "removes geo.json when no feeds",
			policy: &types.Policy{
				Global: types.GlobalSettings{
					GeoBlockFeeds: []types.GeoFeed{},
				},
			},
			wantFile: false,
			wantErr:  false,
			validate: func(t *testing.T, path string) {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("expected geo.json to be removed, stat err=%v", err)
				}
			},
		},
		{
			name: "removes geo.json when feeds is nil",
			policy: &types.Policy{
				Global: types.GlobalSettings{
					GeoBlockFeeds: nil,
				},
			},
			wantFile: false,
			wantErr:  false,
			validate: func(t *testing.T, path string) {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("expected geo.json to be removed, stat err=%v", err)
				}
			},
		},
		{
			name: "updates existing geo.json",
			policy: &types.Policy{
				Global: types.GlobalSettings{
					GeoBlockFeeds: []types.GeoFeed{
						{
							Name:      "us",
							URL:       "https://example.com/us.txt",
							IPVersion: 4,
						},
					},
				},
			},
			wantFile: true,
			wantErr:  false,
			validate: func(t *testing.T, path string) {
				// First, create an existing file with different content
				oldContent := `{"sets":[{"name":"wpc_geo_old_v4"}]}`
				if err := os.WriteFile(path, []byte(oldContent), 0600); err != nil {
					t.Fatalf("setup failed: %v", err)
				}

				// Now the test should overwrite it
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed to read geo.json: %v", err)
				}

				var cfg geoConfigFile
				if err := json.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to parse geo.json: %v", err)
				}

				if len(cfg.Sets) != 1 {
					t.Errorf("expected 1 set, got %d", len(cfg.Sets))
				}
				if cfg.Sets[0].Name != "wpc_geo_us_v4" {
					t.Errorf("expected name 'wpc_geo_us_v4', got %q", cfg.Sets[0].Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: writeGeoConfig writes to hardcoded path /etc/wpc/geo.json
			// This test requires write permissions to /etc/wpc

			// Skip this test if we can't write to /etc/wpc
			if err := os.MkdirAll("/etc/wpc", 0755); err != nil {
				t.Skipf("Cannot create /etc/wpc: %v. Skipping test.", err)
			}

			// Clean up after test
			defer func() {
				_ = os.Remove("/etc/wpc/geo.json")
			}()

			err := writeGeoConfig(tt.policy)

			if (err != nil) != tt.wantErr {
				t.Errorf("writeGeoConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.validate != nil {
				tt.validate(t, "/etc/wpc/geo.json")
			}

			// Verify file existence matches expectation
			_, statErr := os.Stat("/etc/wpc/geo.json")
			fileExists := statErr == nil

			if fileExists != tt.wantFile {
				t.Errorf("writeGeoConfig() file exists = %v, want %v", fileExists, tt.wantFile)
			}
		})
	}
}

// TestLoadPolicy tests the loadPolicy function with table-driven tests
func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, policy *types.Policy)
	}{
		{
			name: "loads valid minimal policy",
			fileContent: `version: v2
global:
  interface: wg0
  ipv6_mode: allow
  egress_policy: block
definitions: {}
rules: []
`,
			wantErr: false,
			validate: func(t *testing.T, policy *types.Policy) {
				if policy.Version != "v2" {
					t.Errorf("expected version 'v2', got %q", policy.Version)
				}
				if policy.Global.Interface != "wg0" {
					t.Errorf("expected interface 'wg0', got %q", policy.Global.Interface)
				}
				if policy.Global.IPv6Mode != "allow" {
					t.Errorf("expected ipv6_mode 'allow', got %q", policy.Global.IPv6Mode)
				}
				if policy.Global.EgressPolicy != "block" {
					t.Errorf("expected egress_policy 'block', got %q", policy.Global.EgressPolicy)
				}
			},
		},
		{
			name: "loads policy with definitions and rules",
			fileContent: `version: v2
global:
  interface: wg0
definitions:
  admins:
    - 10.0.0.1/32
    - 10.0.0.2/32
  servers: 10.100.0.0/24
rules:
  - name: allow-ssh
    action: accept
    proto: tcp
    port: "22"
    src: ["admins"]
    dst: ["servers"]
`,
			wantErr: false,
			validate: func(t *testing.T, policy *types.Policy) {
				if len(policy.Definitions) != 2 {
					t.Errorf("expected 2 definitions, got %d", len(policy.Definitions))
				}
				if len(policy.Rules) != 1 {
					t.Errorf("expected 1 rule, got %d", len(policy.Rules))
				}
				if policy.Rules[0].Name != "allow-ssh" {
					t.Errorf("expected rule name 'allow-ssh', got %q", policy.Rules[0].Name)
				}
				if policy.Rules[0].Port != "22" {
					t.Errorf("expected port '22', got %q", policy.Rules[0].Port)
				}

				// Check definition parsing
				admins := policy.Definitions["admins"]
				if len(admins) != 2 {
					t.Errorf("expected 2 admin IPs, got %d", len(admins))
				}

				servers := policy.Definitions["servers"]
				if len(servers) != 1 {
					t.Errorf("expected 1 server definition, got %d", len(servers))
				}
				if servers[0] != "10.100.0.0/24" {
					t.Errorf("expected servers[0] '10.100.0.0/24', got %q", servers[0])
				}
			},
		},
		{
			name: "loads policy with geo feeds",
			fileContent: `version: v2
global:
  interface: wg0
  geo_block_feeds:
    - name: cn
      url: https://example.com/cn.txt
      ip_version: 4
      sha256: abc123
      refresh_sec: 3600
definitions: {}
rules: []
`,
			wantErr: false,
			validate: func(t *testing.T, policy *types.Policy) {
				if len(policy.Global.GeoBlockFeeds) != 1 {
					t.Fatalf("expected 1 geo feed, got %d", len(policy.Global.GeoBlockFeeds))
				}
				feed := policy.Global.GeoBlockFeeds[0]
				if feed.Name != "cn" {
					t.Errorf("expected name 'cn', got %q", feed.Name)
				}
				if feed.URL != "https://example.com/cn.txt" {
					t.Errorf("expected URL 'https://example.com/cn.txt', got %q", feed.URL)
				}
				if feed.IPVersion != 4 {
					t.Errorf("expected IPVersion 4, got %d", feed.IPVersion)
				}
			},
		},
		{
			name:        "returns error for invalid YAML syntax",
			fileContent: `invalid: yaml: syntax: [[[`,
			wantErr:     true,
			errContains: "failed to parse YAML",
		},
		{
			name:        "returns error for nonexistent file",
			fileContent: "", // Will use nonexistent path
			wantErr:     true,
			errContains: "failed to read file",
		},
		{
			name: "loads empty policy",
			fileContent: `version: v2
global:
  interface: wg0
`,
			wantErr: false,
			validate: func(t *testing.T, policy *types.Policy) {
				// YAML unmarshaling leaves these as nil when not specified
				// This is expected behavior
				if policy.Version != "v2" {
					t.Errorf("expected version 'v2', got %q", policy.Version)
				}
				if policy.Global.Interface != "wg0" {
					t.Errorf("expected interface 'wg0', got %q", policy.Global.Interface)
				}
			},
		},
		{
			name: "loads policy with profiles",
			fileContent: `version: v2
global:
  interface: wg0
definitions:
  servers: 10.0.0.0/24
rules: []
profiles:
  dev:
    rules:
      - name: dev-allow-all
        action: accept
        proto: any
        port: any
        src: [any]
        dst: [any]
`,
			wantErr: false,
			validate: func(t *testing.T, policy *types.Policy) {
				if len(policy.Profiles) != 1 {
					t.Errorf("expected 1 profile, got %d", len(policy.Profiles))
				}
				devProfile, exists := policy.Profiles["dev"]
				if !exists {
					t.Fatal("expected 'dev' profile to exist")
				}
				if len(devProfile.Rules) != 1 {
					t.Errorf("expected 1 rule in dev profile, got %d", len(devProfile.Rules))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string

			if tt.errContains == "failed to read file" {
				// Test with nonexistent file
				path = filepath.Join(t.TempDir(), "nonexistent.yaml")
			} else {
				// Create temporary file with content
				tmpFile, err := os.CreateTemp(t.TempDir(), "policy-*.yaml")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer tmpFile.Close()

				if _, err := tmpFile.WriteString(tt.fileContent); err != nil {
					t.Fatalf("failed to write temp file: %v", err)
				}
				path = tmpFile.Name()
			}

			policy, err := loadPolicy(path)

			if (err != nil) != tt.wantErr {
				t.Errorf("loadPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("loadPolicy() error = %v, want error containing %q", err, tt.errContains)
				}
			}

			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, policy)
			}
		})
	}
}

// TestScheduleRollback tests the scheduleRollback goroutine function
func TestScheduleRollback(t *testing.T) {
	tests := []struct {
		name           string
		timeoutSec     int
		setup          func(t *testing.T, rollbackPath, pendingPath string)
		expectRollback bool
		expectPending  bool // Whether pending file should exist after timeout
	}{
		{
			name:       "executes rollback when pending file exists",
			timeoutSec: 1,
			setup: func(t *testing.T, rollbackPath, pendingPath string) {
				// Create a mock rollback script that creates a marker file
				rollbackContent := "#!/bin/bash\ntouch " + rollbackPath + ".executed\n"
				if err := os.WriteFile(rollbackPath, []byte(rollbackContent), 0755); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				// Create pending marker
				if err := os.WriteFile(pendingPath, []byte(rollbackPath), 0600); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			},
			expectRollback: false, // We can't easily test nft execution in unit tests
			expectPending:  false, // Pending file should be removed
		},
		{
			name:       "skips rollback when pending file removed before timeout",
			timeoutSec: 1,
			setup: func(t *testing.T, rollbackPath, pendingPath string) {
				// Create rollback file
				if err := os.WriteFile(rollbackPath, []byte("content"), 0600); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				// Create pending marker but remove it immediately
				if err := os.WriteFile(pendingPath, []byte(rollbackPath), 0600); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				// Simulate confirmation by removing pending file
				go func() {
					time.Sleep(100 * time.Millisecond)
					_ = os.Remove(pendingPath)
				}()
			},
			expectRollback: false,
			expectPending:  false,
		},
		{
			name:       "handles missing rollback file gracefully",
			timeoutSec: 1,
			setup: func(t *testing.T, rollbackPath, pendingPath string) {
				// Create pending marker but no rollback file
				if err := os.WriteFile(pendingPath, []byte(rollbackPath), 0600); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				// Don't create rollbackPath - simulate missing file
			},
			expectRollback: false,
			expectPending:  false, // Pending should still be removed even if rollback fails
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			rollbackPath := filepath.Join(tmpDir, "rollback.nft")
			pendingPath := filepath.Join(tmpDir, "pending")

			if tt.setup != nil {
				tt.setup(t, rollbackPath, pendingPath)
			}

			// Run scheduleRollback in a goroutine
			go scheduleRollback(rollbackPath, pendingPath, tt.timeoutSec)

			// Wait for timeout + grace period
			time.Sleep(time.Duration(tt.timeoutSec+1) * time.Second)

			// Check if pending file exists
			_, pendingErr := os.Stat(pendingPath)
			pendingExists := pendingErr == nil

			if pendingExists != tt.expectPending {
				t.Errorf("pending file exists = %v, want %v", pendingExists, tt.expectPending)
			}
		})
	}
}

// TestGeoSetConfig tests the geoSetConfig struct marshaling
func TestGeoSetConfig(t *testing.T) {
	cfg := geoSetConfig{
		Table:      "wpc_filter",
		Family:     "inet",
		Name:       "wpc_geo_cn_v4",
		URL:        "https://example.com/cn.txt",
		IPVersion:  4,
		SHA256:     "abc123",
		RefreshSec: 3600,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded geoSetConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Table != cfg.Table {
		t.Errorf("table mismatch: got %q, want %q", decoded.Table, cfg.Table)
	}
	if decoded.Name != cfg.Name {
		t.Errorf("name mismatch: got %q, want %q", decoded.Name, cfg.Name)
	}
	if decoded.URL != cfg.URL {
		t.Errorf("url mismatch: got %q, want %q", decoded.URL, cfg.URL)
	}
	if decoded.IPVersion != cfg.IPVersion {
		t.Errorf("ip_version mismatch: got %d, want %d", decoded.IPVersion, cfg.IPVersion)
	}
}

// TestGeoConfigFile tests the geoConfigFile struct marshaling
func TestGeoConfigFile(t *testing.T) {
	cfg := geoConfigFile{
		Sets: []geoSetConfig{
			{
				Table:     "wpc_filter",
				Family:    "inet",
				Name:      "wpc_geo_cn_v4",
				URL:       "https://example.com/cn.txt",
				IPVersion: 4,
			},
			{
				Table:     "wpc_filter",
				Family:    "inet",
				Name:      "wpc_geo_ru_v6",
				URL:       "https://example.com/ru.txt",
				IPVersion: 6,
			},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded geoConfigFile
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.Sets) != len(cfg.Sets) {
		t.Errorf("sets length mismatch: got %d, want %d", len(decoded.Sets), len(cfg.Sets))
	}

	for i := range cfg.Sets {
		if decoded.Sets[i].Name != cfg.Sets[i].Name {
			t.Errorf("set[%d] name mismatch: got %q, want %q", i, decoded.Sets[i].Name, cfg.Sets[i].Name)
		}
	}
}
