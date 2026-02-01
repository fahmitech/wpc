package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/fahmitech/wpc/pkg/compiler"
	"github.com/fahmitech/wpc/pkg/types"
	"github.com/fahmitech/wpc/pkg/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	unsafeBind bool
	wgConfig   string
	osTarget   string
)

var rootCmd = &cobra.Command{
	Use:   "wpc",
	Short: "WirePolicy Compiler - Declarative network security for WireGuard",
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
		
		err = compiler.ParseAndValidate(policy)
		if err != nil {
			fmt.Printf("[ERROR] Validation failed: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Println("[INFO] Policy is valid.")
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

	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(preflightCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
