package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fahmitech/wpc/pkg/compiler"
	"github.com/fahmitech/wpc/pkg/migration"
	"github.com/fahmitech/wpc/pkg/sentinel"
	"github.com/fahmitech/wpc/pkg/types"
	"github.com/fahmitech/wpc/pkg/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	unsafeBind      bool
	wgConfig        string
	osTarget        string
	monitorInterval int
	initOutput      string
	initForce       bool
	applyFile       string
	applyTimeoutSec int
	profileName     string

	migrateSource   string
	migrateConfig   string
	migrateCIDR     string
	migrateEndpoint string
	migrateOutput   string
	migrateForce    bool
	migratePort     int
)

var rootCmd = &cobra.Command{
	Use:   "wpc",
	Short: "WirePolicy Compiler - Declarative network security for WireGuard",
}

func applyLinuxNFTables(policy *types.Policy, wgConfigPath string, unsafe bool, timeoutSec int) error {
	if err := compiler.ParseAndValidate(policy); err != nil {
		return err
	}

	if !unsafe {
		config, err := utils.ParseWGConfig(wgConfigPath)
		if err != nil {
			fmt.Printf("[WARN] Could not parse WireGuard config: %v. Skipping strict-bind audit.\n", err)
		} else if err := compiler.AuditStrictBind(policy, config); err != nil {
			return fmt.Errorf("%v. Use --unsafe-bind to override", err)
		}
	}

	out, err := compiler.RenderNFTables(policy)
	if err != nil {
		return err
	}

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	rollbackDir := "/etc/wpc/rollback"
	pendingDir := "/etc/wpc/pending"
	rollbackPath := filepath.Join(rollbackDir, fmt.Sprintf("%s.nft", sessionID))
	pendingPath := filepath.Join(pendingDir, fmt.Sprintf("%s", sessionID))

	if err := os.MkdirAll(rollbackDir, 0755); err != nil {
		return fmt.Errorf("failed to create rollback dir: %w", err)
	}
	if err := os.MkdirAll(pendingDir, 0755); err != nil {
		return fmt.Errorf("failed to create pending dir: %w", err)
	}

	// Cleanup on failure
	success := false
	defer func() {
		if !success {
			_ = os.Remove(rollbackPath)
			_ = os.Remove(pendingPath)
		}
	}()

	curr, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		return fmt.Errorf("failed to snapshot current ruleset: %w", err)
	}
	if err := os.WriteFile(rollbackPath, curr, 0600); err != nil {
		return fmt.Errorf("failed to write rollback file: %w", err)
	}

	// Track whether the ruleset was successfully applied. If not, clean up the rollback file
	// to prevent orphaned files in /etc/wpc/rollback/ when operations fail.
	rulesetApplied := false
	defer func() {
		if !rulesetApplied {
			os.Remove(rollbackPath)
		}
	}()

	if err := os.WriteFile("/etc/nftables.conf", []byte(out), 0600); err != nil {
		return fmt.Errorf("failed to write /etc/nftables.conf: %w", err)
	}

	if err := os.MkdirAll("/etc/wpc", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/wpc: %w", err)
	}
	if err := writeGeoConfig(policy); err != nil {
		return err
	}

	if out, err := exec.Command("nft", "-c", "-f", "/etc/nftables.conf").CombinedOutput(); err != nil {
		return fmt.Errorf("nft syntax check failed: %w\n%s", err, string(out))
	}

	if timeoutSec > 0 {
		if err := os.WriteFile(pendingPath, []byte(rollbackPath), 0600); err != nil {
			return fmt.Errorf("failed to write pending marker: %w", err)
		}
		cmd := fmt.Sprintf("sleep %d; if [ -f %s ]; then nft -f %s; rm -f %s; fi", timeoutSec, pendingPath, rollbackPath, pendingPath)
		if err := exec.Command("bash", "-c", cmd).Start(); err != nil {
			return fmt.Errorf("failed to start rollback timer: %w", err)
		}
	}

	if out, err := exec.Command("nft", "-f", "/etc/nftables.conf").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply nftables ruleset: %w\n%s", err, string(out))
	}

	// Ruleset applied successfully, preserve the rollback file for potential manual rollback
	rulesetApplied = true

	if timeoutSec > 0 {
		if err := os.WriteFile(pendingPath, []byte(rollbackPath), 0600); err != nil {
			return fmt.Errorf("failed to write pending marker: %w", err)
		}
		go scheduleRollback(rollbackPath, pendingPath, timeoutSec)
		fmt.Printf("[WARN] Rollback timer armed (%ds). Confirm with: sudo wpc confirm --id %s\n", timeoutSec, sessionID)
	}

	success = true
	return nil
}

// scheduleRollback runs in a goroutine to automatically rollback if not confirmed
func scheduleRollback(rollbackPath, pendingPath string, timeoutSec int) {
	time.Sleep(time.Duration(timeoutSec) * time.Second)

	// Check if still pending
	if _, err := os.Stat(pendingPath); err != nil {
		return // Already confirmed or doesn't exist
	}

	// Execute rollback
	cmd := exec.Command("nft", "-f", rollbackPath)
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Rollback failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[INFO] Rolled back to previous ruleset\n")
	}

	_ = os.Remove(pendingPath)
}

type geoSetConfig struct {
	Table      string `json:"table"`
	Family     string `json:"family"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	IPVersion  int    `json:"ip_version"`
	SHA256     string `json:"sha256,omitempty"`
	RefreshSec int    `json:"refresh_sec,omitempty"`
}

type geoConfigFile struct {
	Sets []geoSetConfig `json:"sets"`
}

func writeGeoConfig(policy *types.Policy) error {
	path := "/etc/wpc/geo.json"
	if len(policy.Global.GeoBlockFeeds) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove geo.json: %w", err)
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
	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("failed to write geo.json: %w", err)
	}
	return nil
}

var checkCmd = &cobra.Command{
	Use:   "check [policy.yaml]",
	Short: "Validate policy syntax and security constraints",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policy, err := loadPolicy(args[0])
		if err != nil {
			return err
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			return err
		}

		if err := compiler.ParseAndValidate(policy); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

		fmt.Println("[INFO] Policy is valid.")
		return nil
	},
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Compile and apply firewall policy with rollback safety",
	RunE: func(cmd *cobra.Command, args []string) error {
		policy, err := loadPolicy(applyFile)
		if err != nil {
			return err
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			return err
		}

		switch osTarget {
		case "linux":
			if err := applyLinuxNFTables(policy, wgConfig, unsafeBind, applyTimeoutSec); err != nil {
				return err
			}
		case "windows":
			return fmt.Errorf("apply is not supported on this platform target. Use `wpc build --os windows` and run the script in an elevated PowerShell")
		default:
			return fmt.Errorf("unsupported OS target: %s", osTarget)
		}

		fmt.Println("[INFO] Policy applied.")
		return nil
	},
}

var confirmCmd = &cobra.Command{
	Use:   "confirm",
	Short: "Confirm last apply to disarm rollback timer",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		found, err := disarmRollback("/etc/wpc/pending", id)
		if err != nil {
			return err
		}
		if !found {
			fmt.Println("[INFO] No pending rollback marker found.")
			return nil
		}
		fmt.Println("[INFO] Rollback disarmed.")
		return nil
	},
}

func disarmRollback(pendingDir string, id string) (bool, error) {
	pendingPath := filepath.Join(pendingDir, id)

	// Validate path to prevent path traversal attacks
	absPendingDir, err := filepath.Abs(pendingDir)
	if err != nil {
		return false, err
	}
	absPendingPath, err := filepath.Abs(pendingPath)
	if err != nil {
		return false, err
	}
	relPath, err := filepath.Rel(absPendingDir, absPendingPath)
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(relPath, "..") || filepath.IsAbs(relPath) {
		return false, fmt.Errorf("invalid id: path traversal detected")
	}

	if err := os.Remove(absPendingPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Start WPC sentinel daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		s := sentinel.New(monitorInterval)
		s.Start(cmd.Context())
		return nil
	},
}

var auditCmd = &cobra.Command{
	Use:   "audit [policy.yaml]",
	Short: "Perform Strict-Bind Audit against WireGuard config",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policy, err := loadPolicy(args[0])
		if err != nil {
			return err
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			return err
		}

		if err := compiler.ParseAndValidate(policy); err != nil {
			return err
		}

		config, err := utils.ParseWGConfig(wgConfig)
		if err != nil {
			return fmt.Errorf("failed to read WG config: %w", err)
		}

		if err := compiler.AuditStrictBind(policy, config); err != nil {
			return fmt.Errorf("audit failed: %w", err)
		}

		fmt.Println("[INFO] Strict-Bind Audit passed.")
		return nil
	},
}

var buildCmd = &cobra.Command{
	Use:   "build [policy.yaml]",
	Short: "Generate platform-specific firewall configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policy, err := loadPolicy(args[0])
		if err != nil {
			return err
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			return err
		}

		if err := compiler.ParseAndValidate(policy); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

		// Perform audit unless unsafe-bind is set
		if !unsafeBind {
			config, err := utils.ParseWGConfig(wgConfig)
			if err == nil {
				if err := compiler.AuditStrictBind(policy, config); err != nil {
					return fmt.Errorf("%v. Use --unsafe-bind to override", err)
				}
			}
		}

		var output string
		switch osTarget {
		case "linux":
			output, err = compiler.RenderNFTables(policy)
		case "windows":
			output, err = compiler.RenderPowerShell(policy)
		default:
			return fmt.Errorf("unsupported OS target: %s", osTarget)
		}

		if err != nil {
			return fmt.Errorf("rendering failed: %w", err)
		}

		fmt.Println(output)
		return nil
	},
}

var preflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Detect potential conflicts with existing firewall setup",
	RunE: func(cmd *cobra.Command, args []string) error {
		rep, err := compiler.PreflightConflicts()
		if err != nil {
			return err
		}
		if rep.HasFirewalld {
			fmt.Println("[WARN] firewalld detected")
		}
		if rep.HasUFW {
			fmt.Println("[WARN] ufw detected")
		}
		if rep.HasDocker {
			fmt.Println("[WARN] docker user chain detected")
		}
		if len(rep.NonWPCTables) > 0 {
			fmt.Printf("[INFO] non-WPC tables: %v\n", rep.NonWPCTables)
		}
		if !(rep.HasFirewalld || rep.HasUFW || rep.HasDocker || len(rep.NonWPCTables) > 0) {
			fmt.Println("[INFO] no obvious conflicts detected")
		}
		return nil
	},
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a skeleton policy.json with safe defaults",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := migration.RunInit(migration.InitRequest{
			WGConfigPath: wgConfig,
			OutputPath:   initOutput,
			Force:        initForce,
		}); err != nil {
			return err
		}
		outPath := initOutput
		if outPath == "" {
			outPath = "policy.json"
		}
		fmt.Printf("[INFO] Wrote %s\n", outPath)
		return nil
	},
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Convert legacy OpenVPN/L2TP configs into wg0.conf and policy.json",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := migration.RunMigrate(migration.MigrateRequest{
			Source:     migrateSource,
			Config:     migrateConfig,
			CIDR:       migrateCIDR,
			Endpoint:   migrateEndpoint,
			ListenPort: migratePort,
			OutputDir:  migrateOutput,
			Force:      migrateForce,
		}); err != nil {
			return err
		}
		fmt.Printf("[INFO] Exported to %s\n", migrateOutput)
		return nil
	},
}

func loadPolicy(path string) (*types.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var policy types.Policy
	err = yaml.Unmarshal(data, &policy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &policy, nil
}

func init() {
	buildCmd.Flags().BoolVar(&unsafeBind, "unsafe-bind", false, "Bypass Strict-Bind Audit")
	buildCmd.Flags().StringVar(&wgConfig, "wg-config", "/etc/wireguard/wg0.conf", "Path to WireGuard config")
	buildCmd.Flags().StringVar(&osTarget, "os", "linux", "Target OS (linux|windows)")

	auditCmd.Flags().StringVar(&wgConfig, "wg-config", "/etc/wireguard/wg0.conf", "Path to WireGuard config")
	checkCmd.Flags().StringVar(&profileName, "profile", "", "Policy profile name")
	auditCmd.Flags().StringVar(&profileName, "profile", "", "Policy profile name")
	buildCmd.Flags().StringVar(&profileName, "profile", "", "Policy profile name")

	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(buildCmd)
	applyCmd.Flags().StringVarP(&applyFile, "file", "f", "", "Policy file path")
	applyCmd.Flags().IntVar(&applyTimeoutSec, "confirm-timeout", 60, "Rollback timeout in seconds (0 disables)")
	applyCmd.Flags().BoolVar(&unsafeBind, "unsafe-bind", false, "Bypass Strict-Bind Audit")
	applyCmd.Flags().StringVar(&wgConfig, "wg-config", "/etc/wireguard/wg0.conf", "Path to WireGuard config")
	applyCmd.Flags().StringVar(&osTarget, "os", "linux", "Target OS (linux|windows)")
	applyCmd.Flags().StringVar(&profileName, "profile", "", "Policy profile name")
	_ = applyCmd.MarkFlagRequired("file")
	rootCmd.AddCommand(applyCmd)
	confirmCmd.Flags().String("id", "", "Apply session ID")
	_ = confirmCmd.MarkFlagRequired("id")
	rootCmd.AddCommand(confirmCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(preflightCmd)
	monitorCmd.Flags().IntVar(&monitorInterval, "interval", 15, "Sentinel interval in seconds")
	rootCmd.AddCommand(monitorCmd)

	initCmd.Flags().StringVar(&wgConfig, "wg-config", "/etc/wireguard/wg0.conf", "Path to WireGuard config")
	initCmd.Flags().StringVar(&initOutput, "output", "policy.json", "Output policy path")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite existing output file")
	rootCmd.AddCommand(initCmd)

	migrateCmd.Flags().StringVar(&migrateSource, "source", "", "Migration source (openvpn|l2tp|pptp)")
	migrateCmd.Flags().StringVar(&migrateConfig, "config", "", "Path to legacy config (index.txt, server.conf, or chap-secrets)")
	migrateCmd.Flags().StringVar(&migrateCIDR, "cidr", "", "WireGuard subnet CIDR (e.g., 10.100.0.0/24)")
	migrateCmd.Flags().StringVar(&migrateEndpoint, "endpoint", "", "Public endpoint IP or hostname for clients")
	migrateCmd.Flags().IntVar(&migratePort, "port", 51820, "WireGuard listen port")
	migrateCmd.Flags().StringVar(&migrateOutput, "output", "/etc/wpc/export", "Export directory")
	migrateCmd.Flags().BoolVar(&migrateForce, "force", false, "Overwrite existing export directory contents")
	rootCmd.AddCommand(migrateCmd)
}

func main() {
	// Setup context with signal handling for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
