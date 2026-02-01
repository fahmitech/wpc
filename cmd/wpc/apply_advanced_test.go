package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fahmitech/wpc/pkg/types"
)

// TestNFTablesCommandGeneration_AdvancedScenarios validates complex policy rendering
func TestNFTablesCommandGeneration_AdvancedScenarios(t *testing.T) {
	// This test validates that various policy configurations generate
	// correct nftables syntax without requiring actual nftables execution

	tests := []struct {
		name   string
		policy *types.Policy
		checks []func(t *testing.T, config string)
	}{
		{
			name: "IPv6 block mode creates drop policy on output chain",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "block",
					EgressPolicy: "allow",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					if !strings.Contains(config, "table ip6 wpc_safety") {
						t.Error("IPv6 safety table missing")
					}
					// When IPv6 mode is block, output chain should have drop policy
					lines := strings.Split(config, "\n")
					var foundOutputChain bool
					for _, line := range lines {
						if strings.Contains(line, "chain output") &&
							strings.Contains(line, "policy drop") {
							foundOutputChain = true
							break
						}
					}
					if !foundOutputChain {
						t.Error("IPv6 block mode should create output chain with drop policy")
					}
				},
			},
		},
		{
			name: "egress block creates restrictive output chain with DNS allowlist",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "block",
					DNSServers:   []string{"1.1.1.1", "8.8.8.8"},
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// Output chain should have drop policy
					if !strings.Contains(config, "chain output") {
						t.Fatal("output chain missing")
					}

					lines := strings.Split(config, "\n")
					var inOutputChain bool
					var hasDropPolicy bool
					var hasDNSRule bool

					for _, line := range lines {
						trimmed := strings.TrimSpace(line)
						if strings.HasPrefix(trimmed, "chain output") {
							inOutputChain = true
						}
						if inOutputChain && strings.Contains(trimmed, "policy drop") {
							hasDropPolicy = true
						}
						if strings.Contains(trimmed, "udp dport 53") &&
							strings.Contains(trimmed, "1.1.1.1") {
							hasDNSRule = true
						}
						if inOutputChain && strings.HasPrefix(trimmed, "chain ") &&
							!strings.HasPrefix(trimmed, "chain output") {
							inOutputChain = false
						}
					}

					if !hasDropPolicy {
						t.Error("egress block mode should set output chain policy to drop")
					}
					if !hasDNSRule {
						t.Error("egress block mode should allow DNS to configured servers")
					}
				},
			},
		},
		{
			name: "bogon protection creates proper sets and drop rules",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:       "wg0",
					IPv6Mode:        "allow",
					EgressPolicy:    "allow",
					BogonInterfaces: []string{"wg0", "eth0"},
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// Should create bogon sets (separate for IPv4 and IPv6)
					if !strings.Contains(config, "set wpc_bogon") {
						t.Error("bogon protection should create wpc_bogon sets")
					}
					// Should have rules matching bogon IPs
					if !strings.Contains(config, "saddr @wpc_bogon") {
						t.Error("bogon protection should have saddr match rules")
					}
					// Should include common bogon ranges
					bogonRanges := []string{
						"10.0.0.0/8",     // RFC 1918
						"192.168.0.0/16", // RFC 1918
						"127.0.0.0/8",    // Loopback
						"169.254.0.0/16", // Link-local
						"224.0.0.0/4",    // Multicast
					}
					for _, bogon := range bogonRanges {
						if !strings.Contains(config, bogon) {
							t.Errorf("bogon set should include %s", bogon)
						}
					}
					// Should match multiple interfaces
					if !strings.Contains(config, "iifname") {
						t.Error("bogon protection should filter by interface")
					}
				},
			},
		},
		{
			name: "geo blocking creates named sets with empty elements",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:          "wg0",
					IPv6Mode:           "allow",
					EgressPolicy:       "allow",
					GeoBlockMode:       "deny",
					GeoBlockInterfaces: []string{"eth0"},
					GeoBlockFeeds: []types.GeoFeed{
						{
							Name:       "cn",
							URL:        "https://example.com/cn.txt",
							IPVersion:  4,
							SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
							RefreshSec: 3600,
						},
						{
							Name:      "ru",
							URL:       "https://example.com/ru.txt",
							IPVersion: 6,
						},
					},
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// Should create named geo sets
					if !strings.Contains(config, "set wpc_geo_cn_v4") {
						t.Error("geo blocking should create wpc_geo_cn_v4 set")
					}
					if !strings.Contains(config, "set wpc_geo_ru_v6") {
						t.Error("geo blocking should create wpc_geo_ru_v6 set")
					}
					// Sets should have empty elements (populated by sentinel)
					lines := strings.Split(config, "\n")
					for i, line := range lines {
						if strings.Contains(line, "set wpc_geo_") {
							// Check next few lines for elements
							found := false
							for j := i; j < len(lines) && j < i+10; j++ {
								if strings.Contains(lines[j], "elements = { }") {
									found = true
									break
								}
							}
							if !found {
								t.Error("geo set should have empty elements initially")
							}
							break
						}
					}
					// Should have drop rules matching the sets
					if !strings.Contains(config, "@wpc_geo_cn_v4 drop") {
						t.Error("geo blocking should create drop rule for cn v4 set")
					}
					if !strings.Contains(config, "@wpc_geo_ru_v6 drop") {
						t.Error("geo blocking should create drop rule for ru v6 set")
					}
				},
			},
		},
		{
			name: "anti-tunneling blocks encapsulation protocols",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:      "wg0",
					IPv6Mode:       "allow",
					EgressPolicy:   "allow",
					AllowTunneling: false,
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// Should block tunnel protocols
					// 41=IPv6-in-IPv4, 47=GRE, 50=ESP, 51=AH
					if !strings.Contains(config, "meta l4proto { 41, 47, 50, 51 } drop") {
						t.Error("anti-tunneling should block tunnel protocols (41, 47, 50, 51)")
					}
				},
			},
		},
		{
			name: "PMTUD allows necessary ICMP messages",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "allow",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// IPv4 ICMP for PMTUD
					if !strings.Contains(config, "destination-unreachable") {
						t.Error("should allow ICMP destination-unreachable for PMTUD")
					}
					if !strings.Contains(config, "time-exceeded") {
						t.Error("should allow ICMP time-exceeded for PMTUD")
					}
					// IPv6 ICMPv6 for PMTUD
					if !strings.Contains(config, "packet-too-big") {
						t.Error("should allow ICMPv6 packet-too-big for PMTUD")
					}
				},
			},
		},
		{
			name: "rules with port ranges generate correct syntax",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "allow",
				},
				Definitions: map[string]types.Definition{
					"web_servers": {"10.0.0.10/32", "10.0.0.11/32"},
				},
				Rules: []types.Rule{
					{
						Name:        "allow-web-ports",
						Action:      "accept",
						Protocol:    "tcp",
						Port:        "8000-8999",
						Source:      []string{"any"},
						Destination: []string{"web_servers"},
					},
				},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// Should generate port range syntax
					if !strings.Contains(config, "tcp dport 8000-8999") {
						t.Error("port range should be formatted correctly as '8000-8999'")
					}
					// Should include both destination IPs
					if !strings.Contains(config, "10.0.0.10") {
						t.Error("destination IP 10.0.0.10 should be in config")
					}
					if !strings.Contains(config, "10.0.0.11") {
						t.Error("destination IP 10.0.0.11 should be in config")
					}
				},
			},
		},
		{
			name: "connection tracking helper disabled for security",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "allow",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// Should disable ct helpers in raw table
					if !strings.Contains(config, `ct helper set "no-helper"`) {
						t.Error("should disable connection tracking helpers for security")
					}
				},
			},
		},
		{
			name: "protect_interface_only allows traffic on other interfaces",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:            "wg0",
					IPv6Mode:             "allow",
					EgressPolicy:         "allow",
					ProtectInterfaceOnly: true,
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			checks: []func(t *testing.T, config string){
				func(t *testing.T, config string) {
					// Should have rule allowing non-wg0 traffic
					if !strings.Contains(config, `iifname != "wg0" accept`) {
						t.Error("protect_interface_only should accept traffic on other interfaces")
					}
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := &mockCommandExecutor{
				ListRulesetOutput:  []byte("# existing"),
				SyntaxCheckOutput:  []byte(""),
				ApplyRulesetOutput: []byte(""),
			}

			mockFS := newMockFileSystemOps()
			tmpDir := t.TempDir()
			config := applyConfig{
				rollbackDir:  filepath.Join(tmpDir, "rollback"),
				pendingDir:   filepath.Join(tmpDir, "pending"),
				nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
				wpcDir:       filepath.Join(tmpDir, "wpc"),
			}

			err := applyLinuxNFTablesInternal(
				tt.policy,
				"",
				true,
				0,
				mockExec,
				mockFS,
				config,
			)

			if err != nil {
				t.Fatalf("applyLinuxNFTables failed: %v", err)
			}

			nftConfig := string(mockFS.Files[config.nftablesConf])

			for _, check := range tt.checks {
				check(t, nftConfig)
			}
		})
	}
}

// TestRollbackCleanupScenarios validates cleanup in various failure modes
func TestRollbackCleanupScenarios(t *testing.T) {
	// This test ensures that rollback files are properly cleaned up
	// in all failure scenarios to prevent orphaned files

	tests := []struct {
		name         string
		setupMock    func(*mockCommandExecutor, *mockFileSystemOps)
		wantErr      bool
		wantRollback bool // Should rollback file remain after error?
		wantPending  bool // Should pending file remain after error?
	}{
		{
			name: "cleanup on policy validation failure",
			setupMock: func(me *mockCommandExecutor, mfs *mockFileSystemOps) {
				// ListRuleset won't be called due to early validation failure
			},
			wantErr:      true,
			wantRollback: false,
			wantPending:  false,
		},
		{
			name: "cleanup on snapshot failure",
			setupMock: func(me *mockCommandExecutor, mfs *mockFileSystemOps) {
				me.ListRulesetError = fmt.Errorf("permission denied")
			},
			wantErr:      true,
			wantRollback: false,
			wantPending:  false,
		},
		{
			name: "cleanup on syntax check failure",
			setupMock: func(me *mockCommandExecutor, mfs *mockFileSystemOps) {
				me.ListRulesetOutput = []byte("# existing")
				me.SyntaxCheckError = fmt.Errorf("syntax error")
			},
			wantErr:      true,
			wantRollback: false,
			wantPending:  false,
		},
		{
			name: "cleanup on apply failure",
			setupMock: func(me *mockCommandExecutor, mfs *mockFileSystemOps) {
				me.ListRulesetOutput = []byte("# existing")
				me.ApplyRulesetError = fmt.Errorf("EBUSY")
			},
			wantErr:      true,
			wantRollback: false, // Should be cleaned up even though we got past syntax check
			wantPending:  false,
		},
		{
			name: "preserve rollback on successful apply",
			setupMock: func(me *mockCommandExecutor, mfs *mockFileSystemOps) {
				me.ListRulesetOutput = []byte("# existing")
			},
			wantErr:      false,
			wantRollback: true, // Keep for manual rollback
			wantPending:  false,
		},
		{
			name: "preserve rollback and pending with timeout",
			setupMock: func(me *mockCommandExecutor, mfs *mockFileSystemOps) {
				me.ListRulesetOutput = []byte("# existing")
			},
			wantErr:      false,
			wantRollback: true,
			wantPending:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := &mockCommandExecutor{
				SyntaxCheckOutput:  []byte(""),
				ApplyRulesetOutput: []byte(""),
			}
			mockFS := newMockFileSystemOps()

			if tt.setupMock != nil {
				tt.setupMock(mockExec, mockFS)
			}

			var policy *types.Policy
			if tt.name == "cleanup on policy validation failure" {
				policy = &types.Policy{
					Version: "v2",
					Global: types.GlobalSettings{
						Interface: "", // Invalid
					},
				}
			} else {
				policy = &types.Policy{
					Version: "v2",
					Global: types.GlobalSettings{
						Interface:    "wg0",
						IPv6Mode:     "allow",
						EgressPolicy: "allow",
					},
					Definitions: map[string]types.Definition{},
					Rules:       []types.Rule{},
				}
			}

			tmpDir := t.TempDir()
			config := applyConfig{
				rollbackDir:  filepath.Join(tmpDir, "rollback"),
				pendingDir:   filepath.Join(tmpDir, "pending"),
				nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
				wpcDir:       filepath.Join(tmpDir, "wpc"),
			}

			timeout := 0
			if tt.wantPending {
				timeout = 60
			}

			err := applyLinuxNFTablesInternal(
				policy,
				"",
				true,
				timeout,
				mockExec,
				mockFS,
				config,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check for rollback file
			var rollbackExists bool
			for path := range mockFS.Files {
				if strings.Contains(path, "rollback") && strings.HasSuffix(path, ".nft") {
					rollbackExists = true
					break
				}
			}

			if rollbackExists != tt.wantRollback {
				t.Errorf("rollback file exists = %v, want %v", rollbackExists, tt.wantRollback)
			}

			// Check for pending file
			var pendingExists bool
			for path := range mockFS.Files {
				if strings.Contains(path, "pending") && !strings.HasSuffix(path, ".nft") {
					pendingExists = true
					break
				}
			}

			if pendingExists != tt.wantPending {
				t.Errorf("pending file exists = %v, want %v", pendingExists, tt.wantPending)
			}
		})
	}
}

// TestGeoConfigWriting validates geo.json generation
func TestGeoConfigWriting(t *testing.T) {
	tests := []struct {
		name      string
		policy    *types.Policy
		wantFile  bool
		checkJSON func(t *testing.T, content string)
	}{
		{
			name: "creates geo.json with feeds",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "allow",
					GeoBlockFeeds: []types.GeoFeed{
						{
							Name:       "cn",
							URL:        "https://example.com/cn.txt",
							IPVersion:  4,
							SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
							RefreshSec: 3600,
						},
					},
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			wantFile: true,
			checkJSON: func(t *testing.T, content string) {
				if !strings.Contains(content, `"name":"wpc_geo_cn_v4"`) {
					t.Error("geo.json should contain set name")
				}
				if !strings.Contains(content, `"url":"https://example.com/cn.txt"`) {
					t.Error("geo.json should contain feed URL")
				}
			},
		},
		{
			name: "removes geo.json when no feeds",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:     "wg0",
					IPv6Mode:      "allow",
					EgressPolicy:  "allow",
					GeoBlockFeeds: []types.GeoFeed{},
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			wantFile: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := &mockCommandExecutor{
				ListRulesetOutput:  []byte("# existing"),
				SyntaxCheckOutput:  []byte(""),
				ApplyRulesetOutput: []byte(""),
			}
			mockFS := newMockFileSystemOps()

			tmpDir := t.TempDir()
			config := applyConfig{
				rollbackDir:  filepath.Join(tmpDir, "rollback"),
				pendingDir:   filepath.Join(tmpDir, "pending"),
				nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
				wpcDir:       filepath.Join(tmpDir, "wpc"),
			}

			err := applyLinuxNFTablesInternal(
				tt.policy,
				"",
				true,
				0,
				mockExec,
				mockFS,
				config,
			)

			if err != nil {
				t.Fatalf("applyLinuxNFTables failed: %v", err)
			}

			geoPath := filepath.Join(config.wpcDir, "geo.json")
			content, exists := mockFS.Files[geoPath]

			if exists != tt.wantFile {
				t.Errorf("geo.json exists = %v, want %v", exists, tt.wantFile)
			}

			if tt.wantFile && tt.checkJSON != nil {
				tt.checkJSON(t, string(content))
			}
		})
	}
}
