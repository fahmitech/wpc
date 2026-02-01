package compiler

import (
	"fmt"
	"net/netip"
	"sort"
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
