package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
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

	curr, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		return fmt.Errorf("failed to snapshot current ruleset: %w", err)
	}
	if err := os.WriteFile(rollbackPath, curr, 0600); err != nil {
		return fmt.Errorf("failed to write rollback file: %w", err)
	}
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

	if timeoutSec > 0 {
		fmt.Printf("[WARN] Rollback timer armed (%ds). Confirm with: sudo wpc confirm --id %s\n", timeoutSec, sessionID)
	}

	return nil
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
	Run: func(cmd *cobra.Command, args []string) {
		policy, err := loadPolicy(args[0])
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		err = compiler.ParseAndValidate(policy)
		if err != nil {
			fmt.Printf("[ERROR] Validation failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[INFO] Policy is valid.")
	},
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Compile and apply firewall policy with rollback safety",
	Run: func(cmd *cobra.Command, args []string) {
		policy, err := loadPolicy(applyFile)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		switch osTarget {
		case "linux":
			if err := applyLinuxNFTables(policy, wgConfig, unsafeBind, applyTimeoutSec); err != nil {
				fmt.Printf("[ERROR] %v\n", err)
				os.Exit(1)
			}
		case "windows":
			fmt.Println("[ERROR] apply is not supported on this platform target. Use `wpc build --os windows` and run the script in an elevated PowerShell.")
			os.Exit(1)
		default:
			fmt.Printf("[ERROR] Unsupported OS target: %s\n", osTarget)
			os.Exit(1)
		}

		fmt.Println("[INFO] Policy applied.")
	},
}

var confirmCmd = &cobra.Command{
	Use:   "confirm",
	Short: "Confirm last apply to disarm rollback timer",
	Run: func(cmd *cobra.Command, args []string) {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			fmt.Println("[ERROR] --id is required")
			os.Exit(1)
		}
		found, err := disarmRollback("/etc/wpc/pending", id)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Println("[INFO] No pending rollback marker found.")
			return
		}
		fmt.Println("[INFO] Rollback disarmed.")
	},
}

func disarmRollback(pendingDir string, id string) (bool, error) {
	pendingPath := filepath.Join(pendingDir, id)
	if err := os.Remove(pendingPath); err != nil {
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
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := sentinel.New(monitorInterval)
		s.Start(ctx)
	},
}

var auditCmd = &cobra.Command{
	Use:   "audit [policy.yaml]",
	Short: "Perform Strict-Bind Audit against WireGuard config",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policy, err := loadPolicy(args[0])
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		err = compiler.ParseAndValidate(policy)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		config, err := utils.ParseWGConfig(wgConfig)
		if err != nil {
			fmt.Printf("[ERROR] Failed to read WG config: %v\n", err)
			os.Exit(1)
		}

		err = compiler.AuditStrictBind(policy, config)
		if err != nil {
			fmt.Printf("[ERROR] Audit failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[INFO] Strict-Bind Audit passed.")
	},
}

var buildCmd = &cobra.Command{
	Use:   "build [policy.yaml]",
	Short: "Generate platform-specific firewall configuration",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policy, err := loadPolicy(args[0])
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		policy, err = compiler.SelectProfile(policy, profileName)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}

		err = compiler.ParseAndValidate(policy)
		if err != nil {
			fmt.Printf("[ERROR] Validation failed: %v\n", err)
			os.Exit(1)
		}

		// Perform audit unless unsafe-bind is set
		if !unsafeBind {
			config, err := utils.ParseWGConfig(wgConfig)
			if err == nil {
				if err := compiler.AuditStrictBind(policy, config); err != nil {
					fmt.Printf("[ERROR] %v. Use --unsafe-bind to override.\n", err)
					os.Exit(1)
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
			fmt.Printf("[ERROR] Unsupported OS target: %s\n", osTarget)
			os.Exit(1)
		}

		if err != nil {
			fmt.Printf("[ERROR] Rendering failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(output)
	},
}

var preflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Detect potential conflicts with existing firewall setup",
	Run: func(cmd *cobra.Command, args []string) {
		rep, err := compiler.PreflightConflicts()
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
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
	},
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a skeleton policy.json with safe defaults",
	Run: func(cmd *cobra.Command, args []string) {
		if err := migration.RunInit(migration.InitRequest{
			WGConfigPath: wgConfig,
			OutputPath:   initOutput,
			Force:        initForce,
		}); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}
		outPath := initOutput
		if outPath == "" {
			outPath = "policy.json"
		}
		fmt.Printf("[INFO] Wrote %s\n", outPath)
	},
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Convert legacy OpenVPN/L2TP configs into wg0.conf and policy.json",
	Run: func(cmd *cobra.Command, args []string) {
		if err := migration.RunMigrate(migration.MigrateRequest{
			Source:     migrateSource,
			Config:     migrateConfig,
			CIDR:       migrateCIDR,
			Endpoint:   migrateEndpoint,
			ListenPort: migratePort,
			OutputDir:  migrateOutput,
			Force:      migrateForce,
		}); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[INFO] Exported to %s\n", migrateOutput)
	},
}

func loadPolicy(path string) (*types.Policy, error) {
	data, err := ioutil.ReadFile(path)
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
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
