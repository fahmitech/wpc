package compiler

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/fahmitech/wpc/pkg/types"
	"github.com/fahmitech/wpc/pkg/utils"
)

// ParseAndValidate takes a raw policy and applies all security checks and logic
func ParseAndValidate(policy *types.Policy) error {
	// 1. Validate Global Settings
	if err := utils.ValidateString(policy.Global.Interface); err != nil {
		return fmt.Errorf("global.interface: %w", err)
	}

	if policy.Global.IPv6Mode == "" {
		policy.Global.IPv6Mode = "allow"
	}
	if policy.Global.EgressPolicy == "" {
		policy.Global.EgressPolicy = "allow"
	}
	switch policy.Global.IPv6Mode {
	case "allow", "block":
	default:
		return fmt.Errorf("global.ipv6_mode: must be allow or block")
	}
	switch policy.Global.EgressPolicy {
	case "allow", "block":
	default:
		return fmt.Errorf("global.egress_policy: must be allow or block")
	}

	for i, iface := range policy.Global.BogonInterfaces {
		if err := utils.ValidateString(iface); err != nil {
			return fmt.Errorf("global.bogon_interfaces[%d]: %w", i, err)
		}
	}

	for i, iface := range policy.Global.GeoBlockInterfaces {
		if err := utils.ValidateString(iface); err != nil {
			return fmt.Errorf("global.geo_block_interfaces[%d]: %w", i, err)
		}
	}

	if policy.Global.GeoBlockMode == "" {
		policy.Global.GeoBlockMode = "deny"
	}
	switch policy.Global.GeoBlockMode {
	case "deny", "allow":
	default:
		return fmt.Errorf("global.geo_block_mode: must be deny or allow")
	}
	if policy.Global.GeoBlockMode == "allow" && len(policy.Global.GeoBlockInterfaces) == 0 {
		return fmt.Errorf("global.geo_block_interfaces: required when geo_block_mode is allow")
	}

	for i, feed := range policy.Global.GeoBlockFeeds {
		if err := utils.ValidateString(feed.Name); err != nil {
			return fmt.Errorf("global.geo_block_feeds[%d].name: %w", i, err)
		}
		u, err := url.Parse(feed.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("global.geo_block_feeds[%d].url: invalid url", i)
		}
		if strings.ToLower(u.Scheme) != "https" {
			return fmt.Errorf("global.geo_block_feeds[%d].url: https is required", i)
		}
		if feed.IPVersion != 4 && feed.IPVersion != 6 {
			return fmt.Errorf("global.geo_block_feeds[%d].ip_version: must be 4 or 6", i)
		}
		if feed.RefreshSec < 0 {
			return fmt.Errorf("global.geo_block_feeds[%d].refresh_sec: must be >= 0", i)
		}
		if feed.SHA256 != "" {
			sum := strings.ToLower(strings.TrimSpace(feed.SHA256))
			if len(sum) != 64 {
				return fmt.Errorf("global.geo_block_feeds[%d].sha256: must be 64 hex chars", i)
			}
			if _, err := hex.DecodeString(sum); err != nil {
				return fmt.Errorf("global.geo_block_feeds[%d].sha256: must be hex", i)
			}
		}
		if feed.SHA256 == "" {
			continue
		}
	}

	for i, dns := range policy.Global.DNSServers {
		if _, err := netip.ParseAddr(dns); err != nil {
			return fmt.Errorf("global.dns_servers[%d]: invalid ip '%s'", i, dns)
		}
	}

	// 2. Validate and Resolve Definitions
	resolvedDefs := make(map[string][]netip.Prefix)
	for name, values := range policy.Definitions {
		if err := utils.ValidateString(name); err != nil {
			return fmt.Errorf("definitions.%s: %w", name, err)
		}
		
		var prefixes []netip.Prefix
		for _, val := range values {
			p, err := parsePrefixOrIP(val)
			if err != nil {
				return fmt.Errorf("definitions.%s: invalid value '%s': %w", name, val, err)
			}
			prefixes = append(prefixes, p)
		}
		resolvedDefs[name] = prefixes
	}

	// 3. Process Rules
	for i := range policy.Rules {
		rule := &policy.Rules[i]
		
		// Validate names/comments
		if rule.Name != "" {
			if err := utils.ValidateString(rule.Name); err != nil {
				return fmt.Errorf("rule[%d].name: %w", i, err)
			}
		}

		rule.Action = strings.ToLower(rule.Action)
		switch rule.Action {
		case "accept", "drop":
		default:
			return fmt.Errorf("rule[%d].action: must be accept or drop", i)
		}

		rule.Protocol = strings.ToLower(rule.Protocol)
		switch rule.Protocol {
		case "any", "tcp", "udp", "icmp", "icmpv6":
		default:
			return fmt.Errorf("rule[%d].proto: must be any, tcp, udp, icmp, or icmpv6", i)
		}

		rule.Port = strings.ToLower(rule.Port)
		if rule.Port == "" {
			rule.Port = "any"
		}
		if rule.Port != "any" {
			if rule.Protocol == "any" {
				return fmt.Errorf("rule[%d].port: cannot specify port when proto is any", i)
			}
			if rule.Protocol == "icmp" || rule.Protocol == "icmpv6" {
				return fmt.Errorf("rule[%d].port: cannot specify port for icmp", i)
			}
			if strings.Contains(rule.Port, "-") {
				parts := strings.Split(rule.Port, "-")
				if len(parts) != 2 {
					return fmt.Errorf("rule[%d].port: invalid range", i)
				}
				a, err := strconv.Atoi(parts[0])
				if err != nil || a < 1 || a > 65535 {
					return fmt.Errorf("rule[%d].port: invalid range start", i)
				}
				b, err := strconv.Atoi(parts[1])
				if err != nil || b < 1 || b > 65535 {
					return fmt.Errorf("rule[%d].port: invalid range end", i)
				}
				if a > b {
					return fmt.Errorf("rule[%d].port: invalid range (start > end)", i)
				}
			} else {
				p, err := strconv.Atoi(rule.Port)
				if err != nil || p < 1 || p > 65535 {
					return fmt.Errorf("rule[%d].port: must be any, a port number, or a range", i)
				}
			}
		}

		// Resolve Sources
		srcPrefixes, err := resolveList(rule.Source, resolvedDefs)
		if err != nil {
			return fmt.Errorf("rule[%d].src: %w", i, err)
		}
		rule.SrcPrefixes = srcPrefixes

		// Resolve Destinations
		dstPrefixes, err := resolveList(rule.Destination, resolvedDefs)
		if err != nil {
			return fmt.Errorf("rule[%d].dst: %w", i, err)
		}
		rule.DstPrefixes = dstPrefixes
	}

	// 4. Spec #5: Sort rules by CIDR specificity (prefix length descending)
	sort.SliceStable(policy.Rules, func(i, j int) bool {
		return getMaxPrefixLen(policy.Rules[i].DstPrefixes) > getMaxPrefixLen(policy.Rules[j].DstPrefixes)
	})

	return nil
}

func parsePrefixOrIP(input string) (netip.Prefix, error) {
	if input == "any" {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), nil
	}
	
	if strings.Contains(input, "/") {
		return netip.ParsePrefix(input)
	}
	
	addr, err := netip.ParseAddr(input)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func resolveList(inputs []string, defs map[string][]netip.Prefix) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, input := range inputs {
		if input == "any" {
			result = append(result, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
			continue
		}
		
		// Check if it's an alias
		if prefixes, ok := defs[input]; ok {
			result = append(result, prefixes...)
			continue
		}
		
		// Try parsing as IP/CIDR
		p, err := parsePrefixOrIP(input)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}

func getMaxPrefixLen(prefixes []netip.Prefix) int {
	max := -1
	for _, p := range prefixes {
		if p.Bits() > max {
			max = p.Bits()
		}
	}
	return max
}
