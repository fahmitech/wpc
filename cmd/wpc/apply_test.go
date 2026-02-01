package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fahmitech/wpc/pkg/types"
)

// mockCommandExecutor implements commandExecutor for testing
type mockCommandExecutor struct {
	ListRulesetOutput  []byte
	ListRulesetError   error
	SyntaxCheckOutput  []byte
	SyntaxCheckError   error
	ApplyRulesetOutput []byte
	ApplyRulesetError  error
	StartTimerError    error

	ListRulesetCalled  bool
	SyntaxCheckCalled  bool
	ApplyRulesetCalled bool
	StartTimerCalled   bool
}

func (m *mockCommandExecutor) ListRuleset() ([]byte, error) {
	m.ListRulesetCalled = true
	return m.ListRulesetOutput, m.ListRulesetError
}

func (m *mockCommandExecutor) SyntaxCheck(configPath string) ([]byte, error) {
	m.SyntaxCheckCalled = true
	return m.SyntaxCheckOutput, m.SyntaxCheckError
}

func (m *mockCommandExecutor) ApplyRuleset(configPath string) ([]byte, error) {
	m.ApplyRulesetCalled = true
	return m.ApplyRulesetOutput, m.ApplyRulesetError
}

func (m *mockCommandExecutor) StartRollbackTimer(rollbackPath, pendingPath string, timeoutSec int) error {
	m.StartTimerCalled = true
	return m.StartTimerError
}

// mockFileSystemOps implements fileSystemOps for testing
type mockFileSystemOps struct {
	Files    map[string][]byte
	Dirs     map[string]bool
	WriteErr map[string]error
	StatErr  map[string]error

	WriteCallCount int
	ReadCallCount  int
}

func newMockFileSystemOps() *mockFileSystemOps {
	return &mockFileSystemOps{
		Files:    make(map[string][]byte),
		Dirs:     make(map[string]bool),
		WriteErr: make(map[string]error),
		StatErr:  make(map[string]error),
	}
}

func (m *mockFileSystemOps) WriteFile(path string, data []byte, perm os.FileMode) error {
	m.WriteCallCount++
	if err, exists := m.WriteErr[path]; exists {
		return err
	}
	m.Files[path] = data
	return nil
}

func (m *mockFileSystemOps) ReadFile(path string) ([]byte, error) {
	m.ReadCallCount++
	if data, exists := m.Files[path]; exists {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (m *mockFileSystemOps) Remove(path string) error {
	delete(m.Files, path)
	return nil
}

func (m *mockFileSystemOps) MkdirAll(path string, perm os.FileMode) error {
	m.Dirs[path] = true
	return nil
}

type mockFileInfo struct {
	name string
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() os.FileMode  { return 0600 }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() interface{}   { return nil }

func (m *mockFileSystemOps) Stat(path string) (os.FileInfo, error) {
	if err, exists := m.StatErr[path]; exists {
		return nil, err
	}
	if _, exists := m.Files[path]; exists {
		return &mockFileInfo{name: filepath.Base(path)}, nil
	}
	return nil, os.ErrNotExist
}

// TestApplyLinuxNFTables_HappyPath validates the complete successful flow
func TestApplyLinuxNFTables_HappyPath(t *testing.T) {
	// This test verifies:
	// - Policy validation passes
	// - Current ruleset is captured for rollback
	// - Generated nftables config passes syntax check
	// - Ruleset is successfully applied
	// - Rollback timer is armed when timeout > 0

	mockExec := &mockCommandExecutor{
		ListRulesetOutput:  []byte("# existing ruleset\ntable inet existing {}"),
		SyntaxCheckOutput:  []byte(""),
		ApplyRulesetOutput: []byte(""),
	}

	mockFS := newMockFileSystemOps()

	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface:    "wg0",
			IPv6Mode:     "allow",
			EgressPolicy: "allow",
		},
		Definitions: map[string]types.Definition{
			"servers": {"10.0.0.0/24"},
		},
		Rules: []types.Rule{
			{
				Name:        "allow-ssh",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "22",
				Source:      []string{"any"},
				Destination: []string{"servers"},
			},
		},
	}

	// Use temporary paths for testing
	tmpDir := t.TempDir()
	config := applyConfig{
		rollbackDir:  filepath.Join(tmpDir, "rollback"),
		pendingDir:   filepath.Join(tmpDir, "pending"),
		nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
		wpcDir:       filepath.Join(tmpDir, "wpc"),
	}

	err := applyLinuxNFTablesInternal(
		policy,
		"",   // wgConfigPath - empty for this test
		true, // unsafe - skip WG config validation
		60,   // timeoutSec
		mockExec,
		mockFS,
		config,
	)

	if err != nil {
		t.Fatalf("applyLinuxNFTables failed: %v", err)
	}

	// Verify command execution order
	if !mockExec.ListRulesetCalled {
		t.Error("expected ListRuleset to be called")
	}
	if !mockExec.SyntaxCheckCalled {
		t.Error("expected SyntaxCheck to be called")
	}
	if !mockExec.ApplyRulesetCalled {
		t.Error("expected ApplyRuleset to be called")
	}
	if !mockExec.StartTimerCalled {
		t.Error("expected StartRollbackTimer to be called with timeout > 0")
	}

	// Verify nftables.conf was written
	nftConfig, exists := mockFS.Files[config.nftablesConf]
	if !exists {
		t.Fatal("expected nftables.conf to be written")
	}

	// Validate generated nftables syntax
	validateNFTablesConfig(t, string(nftConfig))

	// Verify rollback file was created
	var rollbackFound bool
	for path, content := range mockFS.Files {
		if strings.Contains(path, "rollback") && strings.HasSuffix(path, ".nft") {
			rollbackFound = true
			if !bytes.Equal(content, mockExec.ListRulesetOutput) {
				t.Error("rollback file content doesn't match current ruleset")
			}
			break
		}
	}
	if !rollbackFound {
		t.Error("expected rollback file to be created")
	}
}

// validateNFTablesConfig performs syntax validation on generated nftables config
func validateNFTablesConfig(t *testing.T, config string) {
	// This function validates the structure and syntax of generated nftables rules
	// without requiring actual nft binary

	t.Helper()

	// Check for required sections
	requiredSections := []string{
		"flush ruleset",
		"table ip6 wpc_safety",
		"table inet wpc_raw",
		"table inet wpc_filter",
	}

	for _, section := range requiredSections {
		if !strings.Contains(config, section) {
			t.Errorf("nftables config missing required section: %s", section)
		}
	}

	// Verify IPv6 safety table structure
	if !strings.Contains(config, "chain input") {
		t.Error("wpc_safety table missing input chain")
	}
	if !strings.Contains(config, "chain forward") {
		t.Error("wpc_safety table missing forward chain")
	}

	// Verify raw table has defrag rules
	if !strings.Contains(config, "ip defrag") {
		t.Error("wpc_raw table missing ip defrag")
	}
	if !strings.Contains(config, "ip6 defrag") {
		t.Error("wpc_raw table missing ip6 defrag")
	}

	// Verify filter table has proper hook priorities
	if !strings.Contains(config, "priority 0") {
		t.Error("filter chains missing priority declarations")
	}

	// Check for basic security rules
	securityRules := []string{
		"ct state invalid drop",
		"ct state established,related accept",
	}

	for _, rule := range securityRules {
		if !strings.Contains(config, rule) {
			t.Errorf("nftables config missing security rule: %s", rule)
		}
	}

	// Validate no shell injection characters in rules
	// Note: semicolons are valid in nftables syntax (e.g., "policy drop;")
	// We check for shell-specific constructs that shouldn't appear
	dangerousPatterns := []string{"`", "$(", "${", "&&", "||"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(config, pattern) {
			t.Errorf("nftables config contains potentially dangerous pattern: %s", pattern)
		}
	}
}

// TestApplyLinuxNFTables_RollbackOnSyntaxError verifies rollback on syntax check failure
func TestApplyLinuxNFTables_RollbackOnSyntaxError(t *testing.T) {
	// This test ensures that if nft -c -f fails, the rollback file is cleaned up
	// and the function returns an error without applying the ruleset

	mockExec := &mockCommandExecutor{
		ListRulesetOutput: []byte("# existing ruleset"),
		SyntaxCheckOutput: []byte("Error: syntax error, unexpected invalid"),
		SyntaxCheckError:  fmt.Errorf("exit status 1"),
	}

	mockFS := newMockFileSystemOps()

	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface:    "wg0",
			IPv6Mode:     "allow",
			EgressPolicy: "allow",
		},
		Definitions: map[string]types.Definition{},
		Rules:       []types.Rule{},
	}

	tmpDir := t.TempDir()
	config := applyConfig{
		rollbackDir:  filepath.Join(tmpDir, "rollback"),
		pendingDir:   filepath.Join(tmpDir, "pending"),
		nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
		wpcDir:       filepath.Join(tmpDir, "wpc"),
	}

	err := applyLinuxNFTablesInternal(
		policy,
		"",
		true,
		0,
		mockExec,
		mockFS,
		config,
	)

	if err == nil {
		t.Fatal("expected error on syntax check failure")
	}

	if !strings.Contains(err.Error(), "syntax check failed") {
		t.Errorf("expected syntax check error, got: %v", err)
	}

	// Verify apply was NOT called
	if mockExec.ApplyRulesetCalled {
		t.Error("expected apply to be skipped after syntax check failure")
	}

	// Verify rollback file was cleaned up (no rollback files should remain)
	for path := range mockFS.Files {
		if strings.Contains(path, "rollback") && strings.HasSuffix(path, ".nft") {
			t.Error("expected rollback file to be cleaned up after syntax error")
		}
	}
}

// TestApplyLinuxNFTables_ApplyFailureTriggersRollback verifies apply failure handling
func TestApplyLinuxNFTables_ApplyFailureTriggersRollback(t *testing.T) {
	// This test ensures that if the ruleset application fails, proper error
	// is returned and cleanup occurs

	mockExec := &mockCommandExecutor{
		ListRulesetOutput:  []byte("# existing ruleset"),
		SyntaxCheckOutput:  []byte(""),
		ApplyRulesetOutput: []byte("Error: Could not process rule: Device or resource busy"),
		ApplyRulesetError:  fmt.Errorf("exit status 1"),
	}

	mockFS := newMockFileSystemOps()

	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface:    "wg0",
			IPv6Mode:     "allow",
			EgressPolicy: "allow",
		},
		Definitions: map[string]types.Definition{},
		Rules:       []types.Rule{},
	}

	tmpDir := t.TempDir()
	config := applyConfig{
		rollbackDir:  filepath.Join(tmpDir, "rollback"),
		pendingDir:   filepath.Join(tmpDir, "pending"),
		nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
		wpcDir:       filepath.Join(tmpDir, "wpc"),
	}

	err := applyLinuxNFTablesInternal(
		policy,
		"",
		true,
		0,
		mockExec,
		mockFS,
		config,
	)

	if err == nil {
		t.Fatal("expected error on apply failure")
	}

	if !strings.Contains(err.Error(), "failed to apply nftables ruleset") {
		t.Errorf("expected apply failure error, got: %v", err)
	}

	// Verify rollback file was cleaned up
	for path := range mockFS.Files {
		if strings.Contains(path, "rollback") && strings.HasSuffix(path, ".nft") {
			t.Error("expected rollback file to be cleaned up after apply failure")
		}
	}
}

// TestApplyLinuxNFTables_TimeoutBehavior validates rollback timeout mechanism
func TestApplyLinuxNFTables_TimeoutBehavior(t *testing.T) {
	// This test verifies the rollback timeout logic:
	// - When timeout > 0, a pending marker is created
	// - A goroutine is scheduled to rollback after timeout
	// - The timer is armed

	tests := []struct {
		name      string
		timeout   int
		wantTimer bool
	}{
		{
			name:      "timeout disabled (0 seconds)",
			timeout:   0,
			wantTimer: false,
		},
		{
			name:      "timeout enabled (60 seconds)",
			timeout:   60,
			wantTimer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := &mockCommandExecutor{
				ListRulesetOutput:  []byte("# existing ruleset"),
				SyntaxCheckOutput:  []byte(""),
				ApplyRulesetOutput: []byte(""),
			}

			mockFS := newMockFileSystemOps()

			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "allow",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			tmpDir := t.TempDir()
			config := applyConfig{
				rollbackDir:  filepath.Join(tmpDir, "rollback"),
				pendingDir:   filepath.Join(tmpDir, "pending"),
				nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
				wpcDir:       filepath.Join(tmpDir, "wpc"),
			}

			err := applyLinuxNFTablesInternal(
				policy,
				"",
				true,
				tt.timeout,
				mockExec,
				mockFS,
				config,
			)

			if err != nil {
				t.Fatalf("applyLinuxNFTables failed: %v", err)
			}

			// Check if timer was started
			if mockExec.StartTimerCalled != tt.wantTimer {
				t.Errorf("StartRollbackTimer called=%v, want=%v", mockExec.StartTimerCalled, tt.wantTimer)
			}

			// Check if pending marker exists
			var pendingFound bool
			for path := range mockFS.Files {
				if strings.Contains(path, "pending") {
					pendingFound = true
					break
				}
			}

			if pendingFound != tt.wantTimer {
				t.Errorf("pending marker exists=%v, want=%v", pendingFound, tt.wantTimer)
			}
		})
	}
}

// TestApplyLinuxNFTables_PolicyValidation tests various policy validation scenarios
func TestApplyLinuxNFTables_PolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  *types.Policy
		wantErr string
	}{
		{
			name: "missing interface",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface: "",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			wantErr: "interface",
		},
		{
			name: "invalid IPv6 mode",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface: "wg0",
					IPv6Mode:  "invalid",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			wantErr: "ipv6_mode",
		},
		{
			name: "invalid egress policy",
			policy: &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "invalid",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			},
			wantErr: "egress_policy",
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

			if err == nil {
				t.Fatal("expected validation error")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}

			// Verify no commands were executed on validation failure
			if mockExec.ListRulesetCalled {
				t.Error("expected no command execution on validation failure")
			}
		})
	}
}

// TestApplyLinuxNFTables_FileSystemErrors validates error handling for file operations
func TestApplyLinuxNFTables_FileSystemErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(*mockFileSystemOps)
		wantErr   string
	}{
		{
			name: "fails when nftables.conf cannot be written",
			setupMock: func(mfs *mockFileSystemOps) {
				mfs.WriteErr["/tmp/test/nftables.conf"] = fmt.Errorf("read-only filesystem")
			},
			wantErr: "failed to write",
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
			tmpDir := "/tmp/test"
			tt.setupMock(mockFS)

			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					IPv6Mode:     "allow",
					EgressPolicy: "allow",
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			config := applyConfig{
				rollbackDir:  filepath.Join(tmpDir, "rollback"),
				pendingDir:   filepath.Join(tmpDir, "pending"),
				nftablesConf: filepath.Join(tmpDir, "nftables.conf"),
				wpcDir:       filepath.Join(tmpDir, "wpc"),
			}

			err := applyLinuxNFTablesInternal(
				policy,
				"",
				true,
				0,
				mockExec,
				mockFS,
				config,
			)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
