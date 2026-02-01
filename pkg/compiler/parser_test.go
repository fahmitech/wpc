package compiler

import (
	"net/netip"
	"testing"

	"github.com/fahmitech/wpc/pkg/types"
)

// TestParseAndValidate_ValidPolicy tests the happy path with a complete valid policy
func TestParseAndValidate_ValidPolicy(t *testing.T) {
	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface:      "wg0",
			IPv6Mode:       "allow",
			EgressPolicy:   "block",
			DNSServers:     []string{"1.1.1.1", "8.8.8.8"},
			AllowTunneling: true,
		},
		Definitions: map[string]types.Definition{
			"admins":  {"10.0.0.0/8", "192.168.1.50/32"},
			"app":     {"10.100.0.10/32"},
			"db":      {"10.100.0.20/32"},
			"web_dmz": {"172.16.0.0/24"},
		},
		Rules: []types.Rule{
			{
				Name:        "allow-ssh",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "22",
				Source:      []string{"admins"},
				Destination: []string{"app"},
			},
			{
				Name:        "allow-https",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "443",
				Source:      []string{"any"},
				Destination: []string{"web_dmz"},
			},
			{
				Name:        "block-db-from-admins",
				Action:      "drop",
				Protocol:    "tcp",
				Port:        "5432",
				Source:      []string{"admins"},
				Destination: []string{"db"},
			},
		},
	}

	err := ParseAndValidate(policy)
	if err != nil {
		t.Fatalf("expected valid policy to pass, got error: %v", err)
	}

	// Verify defaults were applied
	if policy.Global.IPv6Mode != "allow" {
		t.Errorf("expected ipv6_mode='allow', got '%s'", policy.Global.IPv6Mode)
	}

	// Verify rule normalization
	if policy.Rules[0].Action != "accept" {
		t.Errorf("expected action='accept', got '%s'", policy.Rules[0].Action)
	}
	if policy.Rules[0].Protocol != "tcp" {
		t.Errorf("expected proto='tcp', got '%s'", policy.Rules[0].Protocol)
	}

	// Verify source and destination resolution
	if len(policy.Rules[0].SrcPrefixes) == 0 {
		t.Error("expected SrcPrefixes to be populated")
	}
	if len(policy.Rules[0].DstPrefixes) == 0 {
		t.Error("expected DstPrefixes to be populated")
	}
}

// TestParseAndValidate_GlobalSettingsDefaults tests default value assignment
func TestParseAndValidate_GlobalSettingsDefaults(t *testing.T) {
	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface: "wg0",
			// IPv6Mode and EgressPolicy not set
		},
		Definitions: map[string]types.Definition{},
		Rules:       []types.Rule{},
	}

	err := ParseAndValidate(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if policy.Global.IPv6Mode != "allow" {
		t.Errorf("expected default ipv6_mode='allow', got '%s'", policy.Global.IPv6Mode)
	}
	if policy.Global.EgressPolicy != "allow" {
		t.Errorf("expected default egress_policy='allow', got '%s'", policy.Global.EgressPolicy)
	}
	if policy.Global.GeoBlockMode != "deny" {
		t.Errorf("expected default geo_block_mode='deny', got '%s'", policy.Global.GeoBlockMode)
	}
}

// TestParseAndValidate_InvalidInterface tests interface validation
func TestParseAndValidate_InvalidInterface(t *testing.T) {
	testCases := []struct {
		name      string
		iface     string
		wantError bool
	}{
		{"valid wg0", "wg0", false},
		{"valid eth0", "eth0", false},
		{"valid with dash", "wg-vpn", false},
		{"valid with underscore", "wg_vpn", false},
		{"empty string", "", true},
		{"contains space", "wg 0", true},
		{"contains special char", "wg@0", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface: tc.iface,
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error for interface '%s', got nil", tc.iface)
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error for interface '%s': %v", tc.iface, err)
			}
		})
	}
}

// TestParseAndValidate_IPv6ModeValidation tests IPv6 mode validation
func TestParseAndValidate_IPv6ModeValidation(t *testing.T) {
	testCases := []struct {
		mode      string
		wantError bool
	}{
		{"allow", false},
		{"block", false},
		{"ALLOW", true}, // Case-sensitive validation
		{"deny", true},
		{"invalid", true},
		{"", false}, // Should use default
	}

	for _, tc := range testCases {
		t.Run(tc.mode, func(t *testing.T) {
			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface: "wg0",
					IPv6Mode:  tc.mode,
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error for ipv6_mode '%s', got nil", tc.mode)
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error for ipv6_mode '%s': %v", tc.mode, err)
			}
		})
	}
}

// TestParseAndValidate_EgressPolicyValidation tests egress policy validation
func TestParseAndValidate_EgressPolicyValidation(t *testing.T) {
	testCases := []struct {
		policy    string
		wantError bool
	}{
		{"allow", false},
		{"block", false},
		{"deny", true},
		{"invalid", true},
	}

	for _, tc := range testCases {
		t.Run(tc.policy, func(t *testing.T) {
			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:    "wg0",
					EgressPolicy: tc.policy,
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error for egress_policy '%s', got nil", tc.policy)
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error for egress_policy '%s': %v", tc.policy, err)
			}
		})
	}
}

// TestParseAndValidate_DNSServersValidation tests DNS server IP validation
func TestParseAndValidate_DNSServersValidation(t *testing.T) {
	testCases := []struct {
		name      string
		dns       []string
		wantError bool
	}{
		{"valid IPv4", []string{"1.1.1.1", "8.8.8.8"}, false},
		{"valid IPv6", []string{"2606:4700:4700::1111", "2001:4860:4860::8888"}, false},
		{"mixed", []string{"1.1.1.1", "2606:4700:4700::1111"}, false},
		{"invalid IP", []string{"999.999.999.999"}, true},
		{"invalid format", []string{"not-an-ip"}, true},
		{"empty string", []string{""}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:  "wg0",
					DNSServers: tc.dns,
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error for dns_servers %v, got nil", tc.dns)
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error for dns_servers %v: %v", tc.dns, err)
			}
		})
	}
}

// TestParseAndValidate_GeoBlockFeedsValidation tests GeoIP feed validation
func TestParseAndValidate_GeoBlockFeedsValidation(t *testing.T) {
	testCases := []struct {
		name      string
		feed      types.GeoFeed
		wantError bool
	}{
		{
			name: "valid feed IPv4",
			feed: types.GeoFeed{
				Name:       "us",
				URL:        "https://example.com/us.zone",
				IPVersion:  4,
				RefreshSec: 86400,
			},
			wantError: false,
		},
		{
			name: "valid feed IPv6",
			feed: types.GeoFeed{
				Name:       "us6",
				URL:        "https://example.com/us6.zone",
				IPVersion:  6,
				RefreshSec: 3600,
			},
			wantError: false,
		},
		{
			name: "valid with SHA256",
			feed: types.GeoFeed{
				Name:       "fr",
				URL:        "https://example.com/fr.zone",
				IPVersion:  4,
				SHA256:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				RefreshSec: 86400,
			},
			wantError: false,
		},
		{
			name: "invalid name",
			feed: types.GeoFeed{
				Name:      "us@country",
				URL:       "https://example.com/us.zone",
				IPVersion: 4,
			},
			wantError: true,
		},
		{
			name: "http not https",
			feed: types.GeoFeed{
				Name:      "us",
				URL:       "http://example.com/us.zone",
				IPVersion: 4,
			},
			wantError: true,
		},
		{
			name: "invalid URL",
			feed: types.GeoFeed{
				Name:      "us",
				URL:       "not-a-url",
				IPVersion: 4,
			},
			wantError: true,
		},
		{
			name: "invalid IP version",
			feed: types.GeoFeed{
				Name:      "us",
				URL:       "https://example.com/us.zone",
				IPVersion: 5,
			},
			wantError: true,
		},
		{
			name: "negative refresh",
			feed: types.GeoFeed{
				Name:       "us",
				URL:        "https://example.com/us.zone",
				IPVersion:  4,
				RefreshSec: -1,
			},
			wantError: true,
		},
		{
			name: "invalid SHA256 length",
			feed: types.GeoFeed{
				Name:      "us",
				URL:       "https://example.com/us.zone",
				IPVersion: 4,
				SHA256:    "short",
			},
			wantError: true,
		},
		{
			name: "invalid SHA256 hex",
			feed: types.GeoFeed{
				Name:      "us",
				URL:       "https://example.com/us.zone",
				IPVersion: 4,
				SHA256:    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			},
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:     "wg0",
					GeoBlockFeeds: []types.GeoFeed{tc.feed},
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestParseAndValidate_GeoBlockModeValidation tests geo block mode validation
func TestParseAndValidate_GeoBlockModeValidation(t *testing.T) {
	testCases := []struct {
		name       string
		mode       string
		interfaces []string
		wantError  bool
	}{
		{"deny mode", "deny", nil, false},
		{"allow mode with interfaces", "allow", []string{"eth0"}, false},
		{"allow mode without interfaces", "allow", nil, true},
		{"invalid mode", "block", []string{"eth0"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface:          "wg0",
					GeoBlockMode:       tc.mode,
					GeoBlockInterfaces: tc.interfaces,
				},
				Definitions: map[string]types.Definition{},
				Rules:       []types.Rule{},
			}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestParseAndValidate_DefinitionsValidation tests definition validation
func TestParseAndValidate_DefinitionsValidation(t *testing.T) {
	testCases := []struct {
		name        string
		defName     string
		defValues   []string
		wantError   bool
		errorString string
	}{
		{
			name:      "valid CIDR",
			defName:   "internal",
			defValues: []string{"10.0.0.0/8", "192.168.0.0/16"},
			wantError: false,
		},
		{
			name:      "valid IPs",
			defName:   "servers",
			defValues: []string{"10.0.0.1", "10.0.0.2"},
			wantError: false,
		},
		{
			name:      "valid IPv6",
			defName:   "ipv6nets",
			defValues: []string{"2001:db8::/32", "fe80::1"},
			wantError: false,
		},
		{
			name:      "valid any",
			defName:   "everything",
			defValues: []string{"any"},
			wantError: false,
		},
		{
			name:        "invalid name",
			defName:     "my-def@name",
			defValues:   []string{"10.0.0.0/8"},
			wantError:   true,
			errorString: "definitions.",
		},
		{
			name:        "invalid CIDR",
			defName:     "badcidr",
			defValues:   []string{"999.999.999.999/8"},
			wantError:   true,
			errorString: "definitions.badcidr",
		},
		{
			name:        "invalid format",
			defName:     "badformat",
			defValues:   []string{"not-an-ip"},
			wantError:   true,
			errorString: "definitions.badformat",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &types.Policy{
				Version: "v2",
				Global: types.GlobalSettings{
					Interface: "wg0",
				},
				Definitions: map[string]types.Definition{
					tc.defName: tc.defValues,
				},
				Rules: []types.Rule{},
			}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestParseAndValidate_RuleValidation tests rule validation
func TestParseAndValidate_RuleValidation(t *testing.T) {
	basePolicy := func() *types.Policy {
		return &types.Policy{
			Version: "v2",
			Global: types.GlobalSettings{
				Interface: "wg0",
			},
			Definitions: map[string]types.Definition{
				"servers": {"10.0.0.1"},
			},
			Rules: []types.Rule{},
		}
	}

	testCases := []struct {
		name      string
		rule      types.Rule
		wantError bool
	}{
		{
			name: "valid accept rule",
			rule: types.Rule{
				Name:        "allow-ssh",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "22",
				Source:      []string{"any"},
				Destination: []string{"servers"},
			},
			wantError: false,
		},
		{
			name: "valid drop rule",
			rule: types.Rule{
				Action:      "drop",
				Protocol:    "udp",
				Port:        "53",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: false,
		},
		{
			name: "valid port range",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "8000-9000",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: false,
		},
		{
			name: "valid icmp rule",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "icmp",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: false,
		},
		{
			name: "valid proto any",
			rule: types.Rule{
				Action:      "drop",
				Protocol:    "any",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: false,
		},
		{
			name: "invalid action",
			rule: types.Rule{
				Action:      "allow",
				Protocol:    "tcp",
				Port:        "22",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "invalid protocol",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "sctp",
				Port:        "22",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "port with proto any",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "any",
				Port:        "22",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "port with icmp",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "icmp",
				Port:        "22",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "invalid port number",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "99999",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "invalid port range",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "9000-8000",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "invalid port range format",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "8000-9000-10000",
				Source:      []string{"any"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "invalid source reference",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "22",
				Source:      []string{"undefined-alias"},
				Destination: []string{"any"},
			},
			wantError: true,
		},
		{
			name: "invalid destination IP",
			rule: types.Rule{
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "22",
				Source:      []string{"any"},
				Destination: []string{"999.999.999.999"},
			},
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := basePolicy()
			policy.Rules = []types.Rule{tc.rule}

			err := ParseAndValidate(policy)
			if tc.wantError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestParseAndValidate_RuleSorting tests that rules are sorted by CIDR specificity
func TestParseAndValidate_RuleSorting(t *testing.T) {
	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface: "wg0",
		},
		Definitions: map[string]types.Definition{},
		Rules: []types.Rule{
			{
				Name:        "broad-rule",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "80",
				Source:      []string{"any"},
				Destination: []string{"10.0.0.0/8"}, // /8
			},
			{
				Name:        "specific-rule",
				Action:      "drop",
				Protocol:    "tcp",
				Port:        "80",
				Source:      []string{"any"},
				Destination: []string{"10.0.0.1/32"}, // /32 - most specific
			},
			{
				Name:        "mid-rule",
				Action:      "accept",
				Protocol:    "tcp",
				Port:        "80",
				Source:      []string{"any"},
				Destination: []string{"10.0.0.0/24"}, // /24
			},
		},
	}

	err := ParseAndValidate(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After sorting, should be: specific (/32) -> mid (/24) -> broad (/8)
	if policy.Rules[0].Name != "specific-rule" {
		t.Errorf("expected first rule to be 'specific-rule', got '%s'", policy.Rules[0].Name)
	}
	if policy.Rules[1].Name != "mid-rule" {
		t.Errorf("expected second rule to be 'mid-rule', got '%s'", policy.Rules[1].Name)
	}
	if policy.Rules[2].Name != "broad-rule" {
		t.Errorf("expected third rule to be 'broad-rule', got '%s'", policy.Rules[2].Name)
	}
}

// TestParsePrefixOrIP tests the helper function for parsing IPs and CIDRs
func TestParsePrefixOrIP(t *testing.T) {
	testCases := []struct {
		input     string
		wantError bool
		wantBits  int
	}{
		{"any", false, 0},
		{"10.0.0.0/8", false, 8},
		{"192.168.1.0/24", false, 24},
		{"10.0.0.1", false, 32},
		{"2001:db8::/32", false, 32},
		{"2001:db8::1", false, 128},
		{"invalid", true, 0},
		{"999.999.999.999", true, 0},
		{"10.0.0.0/33", true, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			prefix, err := parsePrefixOrIP(tc.input)
			if tc.wantError {
				if err == nil {
					t.Errorf("expected error for input '%s', got nil", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input '%s': %v", tc.input, err)
				}
				if prefix.Bits() != tc.wantBits {
					t.Errorf("expected %d bits, got %d for input '%s'", tc.wantBits, prefix.Bits(), tc.input)
				}
			}
		})
	}
}

// TestResolveList tests the helper function for resolving definition references
func TestResolveList(t *testing.T) {
	defs := map[string][]netip.Prefix{
		"admins": {
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.168.1.50/32"),
		},
		"servers": {
			netip.MustParsePrefix("10.100.0.10/32"),
		},
	}

	testCases := []struct {
		name      string
		inputs    []string
		wantError bool
		wantCount int
	}{
		{
			name:      "resolve alias",
			inputs:    []string{"admins"},
			wantError: false,
			wantCount: 2,
		},
		{
			name:      "resolve multiple aliases",
			inputs:    []string{"admins", "servers"},
			wantError: false,
			wantCount: 3,
		},
		{
			name:      "resolve any",
			inputs:    []string{"any"},
			wantError: false,
			wantCount: 1,
		},
		{
			name:      "resolve direct IP",
			inputs:    []string{"10.0.0.1"},
			wantError: false,
			wantCount: 1,
		},
		{
			name:      "resolve direct CIDR",
			inputs:    []string{"172.16.0.0/12"},
			wantError: false,
			wantCount: 1,
		},
		{
			name:      "mixed resolution",
			inputs:    []string{"admins", "10.0.0.1", "servers"},
			wantError: false,
			wantCount: 4,
		},
		{
			name:      "undefined alias",
			inputs:    []string{"undefined"},
			wantError: true,
			wantCount: 0,
		},
		{
			name:      "invalid IP",
			inputs:    []string{"999.999.999.999"},
			wantError: true,
			wantCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := resolveList(tc.inputs, defs)
			if tc.wantError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(result) != tc.wantCount {
					t.Errorf("expected %d prefixes, got %d", tc.wantCount, len(result))
				}
			}
		})
	}
}

// TestGetMaxPrefixLen tests the helper function for finding max prefix length
func TestGetMaxPrefixLen(t *testing.T) {
	testCases := []struct {
		name     string
		prefixes []netip.Prefix
		want     int
	}{
		{
			name:     "empty list",
			prefixes: []netip.Prefix{},
			want:     -1,
		},
		{
			name: "single /32",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.1/32"),
			},
			want: 32,
		},
		{
			name: "mixed specificity",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("10.0.0.1/32"),
			},
			want: 32,
		},
		{
			name: "IPv6",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
				netip.MustParsePrefix("2001:db8::1/128"),
			},
			want: 128,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getMaxPrefixLen(tc.prefixes)
			if got != tc.want {
				t.Errorf("expected %d, got %d", tc.want, got)
			}
		})
	}
}
