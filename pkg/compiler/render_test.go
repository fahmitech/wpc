package compiler

import (
	"strings"
	"strconv"
	"testing"

	"github.com/fahmitech/wpc/pkg/types"
)

func TestRenderNFTables_EgressBlockIncludesStateInvalidLoopbackDNSAndLogging(t *testing.T) {
	policy := &types.Policy{
		Version: "test",
		Global: types.GlobalSettings{
			Interface:      "wg0",
			IPv6Mode:       "allow",
			EgressPolicy:   "block",
			DNSServers:     []string{"1.1.1.1", "2606:4700:4700::1111"},
			AllowTunneling: true,
		},
		Definitions: map[string]types.Definition{},
		Rules:       []types.Rule{},
	}

	out, err := RenderNFTables(policy)
	if err != nil {
		t.Fatalf("RenderNFTables() error: %v", err)
	}

	wantContains := []string{
		"ct state invalid drop",
		"ct state established,related accept",
		"iifname \"lo\" accept",
		"oifname \"lo\" accept",
		"udp dport 53 ip daddr { 1.1.1.1 } accept",
		"tcp dport 53 ip daddr { 1.1.1.1 } accept",
		"udp dport 53 ip6 daddr { 2606:4700:4700::1111 } accept",
		"tcp dport 53 ip6 daddr { 2606:4700:4700::1111 } accept",
		"limit rate 5/minute burst 10 packets log prefix \"WPC_DROP_IN: \"",
		"limit rate 5/minute burst 10 packets log prefix \"WPC_DROP_OUT: \"",
	}
	for _, s := range wantContains {
		if !strings.Contains(out, s) {
			t.Fatalf("expected nft output to contain %q\n--- output ---\n%s", s, out)
		}
	}
}

func TestRenderPowerShell_NoForwardDirectionAndAddsDNSWhenOutboundBlocked(t *testing.T) {
	policy := &types.Policy{
		Version: "test",
		Global: types.GlobalSettings{
			Interface:      "wg0",
			IPv6Mode:       "allow",
			EgressPolicy:   "block",
			DNSServers:     []string{"1.1.1.1", "2606:4700:4700::1111"},
			AllowTunneling: true,
		},
		Definitions: map[string]types.Definition{},
		Rules: []types.Rule{
			{
				Name:        "Allow-SSH",
				Action:      "accept",
				Protocol:    "tcp",
				Source:      []string{"10.0.0.0/8"},
				Destination: []string{"10.0.0.1"},
				Port:        "22",
			},
		},
	}

	if err := ParseAndValidate(policy); err != nil {
		t.Fatalf("ParseAndValidate() error: %v", err)
	}

	out, err := RenderPowerShell(policy)
	if err != nil {
		t.Fatalf("RenderPowerShell() error: %v", err)
	}

	if strings.Contains(out, "-Direction Forward") {
		t.Fatalf("expected PowerShell output not to contain Forward direction\n--- output ---\n%s", out)
	}

	wantContains := []string{
		"Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block",
		"Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Block",
		"Set-NetFirewallProfile -Profile Private -LogFileName",
		"New-NetFirewallRule -DisplayName \"Allow-SSH\" -Direction Inbound -Action Allow -Protocol tcp -InterfaceAlias \"wg0\" -LocalPort 22 -RemoteAddress 10.0.0.0/8 -LocalAddress 10.0.0.1/32 -Group $ID",
		"New-NetFirewallRule -DisplayName \"WPC-DNS-UDP\" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53",
		"New-NetFirewallRule -DisplayName \"WPC-DNS-TCP\" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53",
		"-InterfaceAlias \"wg0\" -Group $ID",
	}
	for _, s := range wantContains {
		if !strings.Contains(out, s) {
			t.Fatalf("expected PowerShell output to contain %q\n--- output ---\n%s", s, out)
		}
	}
}

func TestRenderNFTables_DualStackRuleRendersSeparateLines(t *testing.T) {
	policy := &types.Policy{
		Version: "test",
		Global: types.GlobalSettings{
			Interface:      "wg0",
			IPv6Mode:       "allow",
			EgressPolicy:   "allow",
			AllowTunneling: true,
		},
		Definitions: map[string]types.Definition{},
		Rules: []types.Rule{
			{
				Name:        "dual-stack",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "443",
				Source:      []string{"10.0.0.0/8", "2001:db8::/32"},
			},
		},
	}
	if err := ParseAndValidate(policy); err != nil {
		t.Fatalf("ParseAndValidate() error: %v", err)
	}
	out, err := RenderNFTables(policy)
	if err != nil {
		t.Fatalf("RenderNFTables() error: %v", err)
	}
	if !strings.Contains(out, "ip saddr") || !strings.Contains(out, "ip6 saddr") {
		t.Fatalf("expected both ipv4 and ipv6 rules\n--- output ---\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "ip saddr") && strings.Contains(line, "ip6 saddr") {
			t.Fatalf("expected ipv4 and ipv6 constraints to be in separate rules, got: %s", line)
		}
	}
}

func TestRenderNFTables_BogonInterfacesAndProtectInterfaceOnly(t *testing.T) {
	policy := &types.Policy{
		Version: "test",
		Global: types.GlobalSettings{
			Interface:            "wg0",
			IPv6Mode:             "allow",
			EgressPolicy:         "allow",
			AllowTunneling:       true,
			BogonInterfaces:      []string{"eth0"},
			ProtectInterfaceOnly: true,
		},
		Definitions: map[string]types.Definition{},
		Rules:       []types.Rule{},
	}
	if err := ParseAndValidate(policy); err != nil {
		t.Fatalf("ParseAndValidate() error: %v", err)
	}
	out, err := RenderNFTables(policy)
	if err != nil {
		t.Fatalf("RenderNFTables() error: %v", err)
	}
	wantContains := []string{
		"set wpc_bogon4_",
		"set wpc_bogon6_",
		"iifname \"eth0\" ip saddr @wpc_bogon4_",
		"iifname \"eth0\" ip6 saddr @wpc_bogon6_",
		"iifname != \"wg0\" accept",
	}
	for _, s := range wantContains {
		if !strings.Contains(out, s) {
			t.Fatalf("expected nft output to contain %q\n--- output ---\n%s", s, out)
		}
	}
}

func TestRenderNFTables_UsesNamedSetForLargeAddressList(t *testing.T) {
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, "10.0.0."+strconv.Itoa(i)+"/32")
	}
	policy := &types.Policy{
		Version: "test",
		Global: types.GlobalSettings{
			Interface:      "wg0",
			IPv6Mode:       "allow",
			EgressPolicy:   "allow",
			AllowTunneling: true,
		},
		Definitions: map[string]types.Definition{
			"many": many,
		},
		Rules: []types.Rule{
			{
				Name:        "large-src",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "22",
				Source:      []string{"many"},
				Destination: []string{"10.0.0.1/32"},
			},
		},
	}
	if err := ParseAndValidate(policy); err != nil {
		t.Fatalf("ParseAndValidate() error: %v", err)
	}
	out, err := RenderNFTables(policy)
	if err != nil {
		t.Fatalf("RenderNFTables() error: %v", err)
	}
	if !strings.Contains(out, "set wpc_src_") || !strings.Contains(out, "ip saddr @wpc_src_") {
		t.Fatalf("expected nft output to use a named set for large src list\n--- output ---\n%s", out)
	}
}

func TestRenderNFTables_GeoBlockRendersSetAndDropRule(t *testing.T) {
	policy := &types.Policy{
		Version: "test",
		Global: types.GlobalSettings{
			Interface:          "wg0",
			IPv6Mode:           "allow",
			EgressPolicy:       "allow",
			AllowTunneling:     true,
			GeoBlockInterfaces: []string{"eth0"},
			GeoBlockFeeds: []types.GeoFeed{
				{
					Name:      "ru",
					URL:       "https://example.com/ru.zone",
					IPVersion: 4,
				},
			},
		},
		Definitions: map[string]types.Definition{},
		Rules:       []types.Rule{},
	}

	if err := ParseAndValidate(policy); err != nil {
		t.Fatalf("ParseAndValidate() error: %v", err)
	}
	out, err := RenderNFTables(policy)
	if err != nil {
		t.Fatalf("RenderNFTables() error: %v", err)
	}
	wantContains := []string{
		"set wpc_geo_ru_v4 {",
		"type ipv4_addr",
		"elements = { }",
		"iifname \"eth0\" ip saddr @wpc_geo_ru_v4 drop",
	}
	for _, s := range wantContains {
		if !strings.Contains(out, s) {
			t.Fatalf("expected nft output to contain %q\n--- output ---\n%s", s, out)
		}
	}
}

func TestRenderNFTables_GeoAllowRendersAcceptAndCatchAllDrop(t *testing.T) {
	policy := &types.Policy{
		Version: "test",
		Global: types.GlobalSettings{
			Interface:          "wg0",
			IPv6Mode:           "allow",
			EgressPolicy:       "allow",
			AllowTunneling:     true,
			GeoBlockMode:       "allow",
			GeoBlockInterfaces: []string{"eth0"},
			GeoBlockFeeds: []types.GeoFeed{
				{
					Name:      "fr",
					URL:       "https://example.com/fr.zone",
					IPVersion: 4,
				},
			},
		},
		Definitions: map[string]types.Definition{},
		Rules:       []types.Rule{},
	}

	if err := ParseAndValidate(policy); err != nil {
		t.Fatalf("ParseAndValidate() error: %v", err)
	}
	out, err := RenderNFTables(policy)
	if err != nil {
		t.Fatalf("RenderNFTables() error: %v", err)
	}
	wantContains := []string{
		"iifname \"eth0\" ip saddr @wpc_geo_fr_v4 accept",
		"iifname \"eth0\" ip saddr 0.0.0.0/0 drop",
		"iifname \"eth0\" ip6 saddr ::/0 drop",
	}
	for _, s := range wantContains {
		if !strings.Contains(out, s) {
			t.Fatalf("expected nft output to contain %q\n--- output ---\n%s", s, out)
		}
	}
}
