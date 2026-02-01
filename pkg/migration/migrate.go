package migration

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fahmitech/wpc/pkg/types"
	"github.com/fahmitech/wpc/pkg/utils"
)

type MigrateRequest struct {
	Source   string
	Config   string
	CIDR     string
	Endpoint string

	ListenPort int
	OutputDir  string
	Force      bool
}

func RunMigrate(req MigrateRequest) error {
	if req.ListenPort == 0 {
		req.ListenPort = 51820
	}
	if req.OutputDir == "" {
		req.OutputDir = "/etc/wpc/export"
	}
	if req.Source == "" {
		return fmt.Errorf("missing source")
	}
	if req.Config == "" {
		return fmt.Errorf("missing config path")
	}
	if req.CIDR == "" {
		return fmt.Errorf("missing cidr")
	}
	if req.Endpoint == "" {
		return fmt.Errorf("missing endpoint")
	}

	network, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		return fmt.Errorf("invalid cidr %q: %w", req.CIDR, err)
	}

	var identities []string
	switch strings.ToLower(req.Source) {
	case "openvpn":
		identities, err = ParseOpenVPNIdentities(req.Config)
	case "l2tp", "pptp":
		identities, err = ParseChapSecretsIdentities(req.Config)
	default:
		return fmt.Errorf("unsupported source %q (expected openvpn, l2tp, pptp)", req.Source)
	}
	if err != nil {
		return err
	}

	safeNames := make([]string, 0, len(identities))
	nameSeen := make(map[string]int)
	for _, id := range identities {
		n, err := SafePeerName(id)
		if err != nil {
			return err
		}
		if c, ok := nameSeen[n]; ok {
			c++
			nameSeen[n] = c
			n = fmt.Sprintf("%s_%d", n, c)
		} else {
			nameSeen[n] = 0
		}
		safeNames = append(safeNames, n)
	}

	sort.Strings(safeNames)

	ipPlan, err := PlanIPs(network, len(safeNames))
	if err != nil {
		return err
	}

	serverKeys, err := GenerateKeypair()
	if err != nil {
		return err
	}

	clientKeys := make(map[string]*Keypair, len(safeNames))
	for _, n := range safeNames {
		kp, err := GenerateKeypair()
		if err != nil {
			return err
		}
		clientKeys[n] = kp
	}

	peerIPs := make(map[string]netip.Addr, len(safeNames))
	for i, n := range safeNames {
		peerIPs[n] = ipPlan.ClientIPs[i]
	}

	endpointHostPort, effectivePort, err := normalizeEndpoint(req.Endpoint, req.ListenPort)
	if err != nil {
		return err
	}

	wgServer, err := renderServerWGConfig(serverKeys.PrivateKeyBase64, ipPlan, effectivePort, clientKeys, peerIPs)
	if err != nil {
		return err
	}

	policy, err := buildSkeletonPolicy(ipPlan, peerIPs)
	if err != nil {
		return err
	}
	policyBytes, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	policyBytes = append(policyBytes, '\n')

	if err := writeExport(req.OutputDir, req.Force, wgServer, policyBytes, serverKeys.PublicKeyBase64, endpointHostPort, ipPlan, clientKeys, peerIPs); err != nil {
		return err
	}

	return nil
}

type InitRequest struct {
	WGConfigPath string
	OutputPath   string
	Force        bool
}

func RunInit(req InitRequest) error {
	if req.OutputPath == "" {
		req.OutputPath = "policy.json"
	}

	if !req.Force {
		if _, err := os.Stat(req.OutputPath); err == nil {
			return fmt.Errorf("output path %s already exists (use --force to overwrite)", req.OutputPath)
		}
	}

	defs := map[string]types.Definition{}
	if req.WGConfigPath != "" {
		if _, err := os.Stat(req.WGConfigPath); err == nil {
			cfg, err := utils.ParseWGConfig(req.WGConfigPath)
			if err != nil {
				return fmt.Errorf("read wg config: %w", err)
			}
			idx := 1
			for _, p := range cfg.Peers {
				for _, allowed := range p.AllowedIPs {
					if allowed.Addr().Is4() && allowed.Bits() == 32 {
						defs[fmt.Sprintf("peer_%d", idx)] = types.Definition{allowed.Addr().String()}
						idx++
						break
					}
				}
			}
		}
	}

	policy := &types.Policy{
		Version: "2.0",
		Global: types.GlobalSettings{
			Interface:        "wg0",
			IPv6Mode:         "block",
			EgressPolicy:     "block",
			DNSServers:       nil,
			AllowTunneling:   false,
			SentinelInterval: 15,
		},
		Definitions: defs,
		Rules:       nil,
	}

	b, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	b = append(b, '\n')

	if err := os.MkdirAll(filepath.Dir(req.OutputPath), 0o755); err != nil && filepath.Dir(req.OutputPath) != "." {
		return fmt.Errorf("create output dir: %w", err)
	}
	if err := os.WriteFile(req.OutputPath, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", req.OutputPath, err)
	}
	return nil
}

func buildSkeletonPolicy(ipPlan *IPPlan, peers map[string]netip.Addr) (*types.Policy, error) {
	defs := make(map[string]types.Definition, len(peers)+2)
	defs["server"] = types.Definition{ipPlan.ServerIP.String()}
	defs["wg_network"] = types.Definition{ipPlan.Network.String()}
	for name, ip := range peers {
		defs[name] = types.Definition{ip.String()}
	}

	return &types.Policy{
		Version: "2.0",
		Global: types.GlobalSettings{
			Interface:        "wg0",
			IPv6Mode:         "block",
			EgressPolicy:     "block",
			DNSServers:       nil,
			AllowTunneling:   false,
			SentinelInterval: 15,
		},
		Definitions: defs,
		Rules:       nil,
	}, nil
}
