package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/fahmitech/wpc/pkg/compiler"
	"github.com/fahmitech/wpc/pkg/types"
	"github.com/fahmitech/wpc/pkg/utils"
)

// commandExecutor abstracts exec.Command operations for testing
type commandExecutor interface {
	ListRuleset() ([]byte, error)
	SyntaxCheck(configPath string) ([]byte, error)
	ApplyRuleset(configPath string) ([]byte, error)
	StartRollbackTimer(rollbackPath, pendingPath string, timeoutSec int) error
}

// fileSystemOps abstracts filesystem operations for testing
type fileSystemOps interface {
	WriteFile(path string, data []byte, perm os.FileMode) error
	ReadFile(path string) ([]byte, error)
	Remove(path string) error
	MkdirAll(path string, perm os.FileMode) error
	Stat(path string) (os.FileInfo, error)
}

// realCommandExecutor implements commandExecutor using actual exec.Command
type realCommandExecutor struct{}

func (e *realCommandExecutor) ListRuleset() ([]byte, error) {
	return exec.Command("nft", "list", "ruleset").Output()
}

func (e *realCommandExecutor) SyntaxCheck(configPath string) ([]byte, error) {
	return exec.Command("nft", "-c", "-f", configPath).CombinedOutput()
}

func (e *realCommandExecutor) ApplyRuleset(configPath string) ([]byte, error) {
	return exec.Command("nft", "-f", configPath).CombinedOutput()
}

func (e *realCommandExecutor) StartRollbackTimer(rollbackPath, pendingPath string, timeoutSec int) error {
	cmd := fmt.Sprintf("sleep %d; if [ -f %s ]; then nft -f %s; rm -f %s; fi",
		timeoutSec, pendingPath, rollbackPath, pendingPath)
	return exec.Command("bash", "-c", cmd).Start()
}

// realFileSystemOps implements fileSystemOps using actual os functions
type realFileSystemOps struct{}

func (f *realFileSystemOps) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (f *realFileSystemOps) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (f *realFileSystemOps) Remove(path string) error {
	return os.Remove(path)
}

func (f *realFileSystemOps) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (f *realFileSystemOps) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// applyConfig holds configuration paths for testing
type applyConfig struct {
	rollbackDir  string
	pendingDir   string
	nftablesConf string
	wpcDir       string
}

// defaultApplyConfig returns production paths
func defaultApplyConfig() applyConfig {
	return applyConfig{
		rollbackDir:  "/etc/wpc/rollback",
		pendingDir:   "/etc/wpc/pending",
		nftablesConf: "/etc/nftables.conf",
		wpcDir:       "/etc/wpc",
	}
}

// applyLinuxNFTablesInternal is the testable implementation
func applyLinuxNFTablesInternal(
	policy *types.Policy,
	wgConfigPath string,
	unsafe bool,
	timeoutSec int,
	executor commandExecutor,
	fs fileSystemOps,
	config applyConfig,
) error {
	// 1. Validate policy
	if err := compiler.ParseAndValidate(policy); err != nil {
		return err
	}

	// 2. Audit strict-bind unless unsafe flag is set
	if !unsafe {
		wgConfig, err := utils.ParseWGConfig(wgConfigPath)
		if err != nil {
			fmt.Printf("[WARN] Could not parse WireGuard config: %v. Skipping strict-bind audit.\n", err)
		} else if err := compiler.AuditStrictBind(policy, wgConfig); err != nil {
			return fmt.Errorf("%v. Use --unsafe-bind to override", err)
		}
	}

	// 3. Render nftables configuration
	out, err := compiler.RenderNFTables(policy)
	if err != nil {
		return err
	}

	// 4. Generate session ID and paths
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	rollbackPath := filepath.Join(config.rollbackDir, fmt.Sprintf("%s.nft", sessionID))
	pendingPath := filepath.Join(config.pendingDir, sessionID)

	// 5. Create necessary directories
	if err := fs.MkdirAll(config.rollbackDir, 0755); err != nil {
		return fmt.Errorf("failed to create rollback dir: %w", err)
	}
	if err := fs.MkdirAll(config.pendingDir, 0755); err != nil {
		return fmt.Errorf("failed to create pending dir: %w", err)
	}

	// 6. Track success for cleanup
	success := false
	defer func() {
		if !success {
			_ = fs.Remove(rollbackPath)
			_ = fs.Remove(pendingPath)
		}
	}()

	// 7. Capture current ruleset for rollback
	currentRuleset, err := executor.ListRuleset()
	if err != nil {
		return fmt.Errorf("failed to snapshot current ruleset: %w", err)
	}

	if err := fs.WriteFile(rollbackPath, currentRuleset, 0600); err != nil {
		return fmt.Errorf("failed to write rollback file: %w", err)
	}

	// 8. Track whether ruleset was successfully applied
	rulesetApplied := false
	defer func() {
		if !rulesetApplied {
			_ = fs.Remove(rollbackPath)
		}
	}()

	// 9. Write nftables configuration
	if err := fs.WriteFile(config.nftablesConf, []byte(out), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", config.nftablesConf, err)
	}

	// 10. Create WPC directory and write geo config
	if err := fs.MkdirAll(config.wpcDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", config.wpcDir, err)
	}

	if err := writeGeoConfigInternal(policy, fs, config.wpcDir); err != nil {
		return err
	}

	// 11. Syntax check
	syntaxOutput, err := executor.SyntaxCheck(config.nftablesConf)
	if err != nil {
		return fmt.Errorf("nft syntax check failed: %w\n%s", err, string(syntaxOutput))
	}

	// 12. Apply ruleset
	applyOutput, err := executor.ApplyRuleset(config.nftablesConf)
	if err != nil {
		return fmt.Errorf("failed to apply nftables ruleset: %w\n%s", err, string(applyOutput))
	}

	// 14. Mark as successfully applied
	rulesetApplied = true
	success = true

	// 15. Update pending marker and schedule rollback goroutine
	if timeoutSec > 0 {
		if err := fs.WriteFile(pendingPath, []byte(rollbackPath), 0600); err != nil {
			// Rollback since rules are live but we can't schedule automatic rollback
			_, _ = executor.ApplyRuleset(rollbackPath)
			return fmt.Errorf("failed to write pending marker (rolled back): %w", err)
		}
		go scheduleRollbackInternal(rollbackPath, pendingPath, timeoutSec, executor, fs)
		fmt.Printf("[WARN] Rollback timer armed (%ds). Confirm with: sudo wpc confirm --id %s\n", timeoutSec, sessionID)
	}

	success = true
	return nil
}

// scheduleRollbackInternal is the testable version of scheduleRollback
func scheduleRollbackInternal(
	rollbackPath string,
	pendingPath string,
	timeoutSec int,
	executor commandExecutor,
	fs fileSystemOps,
) {
	time.Sleep(time.Duration(timeoutSec) * time.Second)

	// Atomically remove pending file - if removal fails, check why
	if err := fs.Remove(pendingPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return // File already removed, user confirmed
		}
		// For other errors (permission, I/O), log and continue with rollback
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to remove pending file: %v\n", err)
	}

	// Execute rollback
	if _, err := executor.ApplyRuleset(rollbackPath); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Rollback failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] Rolled back to previous ruleset\n")
	}
	_ = fs.Remove(rollbackPath)
}

// writeGeoConfigInternal is the testable version of writeGeoConfig
func writeGeoConfigInternal(policy *types.Policy, fs fileSystemOps, wpcDir string) error {
	path := filepath.Join(wpcDir, "geo.json")

	if len(policy.Global.GeoBlockFeeds) == 0 {
		if err := fs.Remove(path); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove geo.json: %w", err)
			}
		}
		return nil
	}

	var cfg geoConfigFile
	for _, feed := range policy.Global.GeoBlockFeeds {
		cfg.Sets = append(cfg.Sets, geoSetConfig{
			Table:      "wpc_filter",
			Family:     "inet",
			Name:       compiler.GeoSetName(feed),
			URL:        feed.URL,
			IPVersion:  feed.IPVersion,
			SHA256:     feed.SHA256,
			RefreshSec: feed.RefreshSec,
		})
	}

	b, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal geo config: %w", err)
	}

	if err := fs.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("failed to write geo.json: %w", err)
	}

	return nil
}
