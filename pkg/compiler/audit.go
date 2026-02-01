package compiler

import (
	"fmt"
	"net/netip"

	"github.com/fahmitech/wpc/pkg/types"
	"github.com/fahmitech/wpc/pkg/utils"
)

// AuditStrictBind verifies that policy IPs match WireGuard AllowedIPs exactly (Spec #11)
func AuditStrictBind(policy *types.Policy, wgConfig *utils.WGConfig) error {
	// Create a lookup map for AllowedIPs -> Peer
	allowedIPMap := make(map[netip.Prefix]string)
	for _, peer := range wgConfig.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedIPMap[prefix] = peer.PublicKey
		}
	}

	for i, rule := range policy.Rules {
		for _, srcPrefix := range rule.SrcPrefixes {
			// Skip "any" (0.0.0.0/0) for audit as it's explicitly broad
			if srcPrefix.Bits() == 0 {
				continue
			}

			// Check if this prefix exists exactly in the WG config
			pubKey, exists := allowedIPMap[srcPrefix]
			if !exists {
				// Check if it's covered by a broader prefix (Spoofing risk)
				for allowedPrefix, pk := range allowedIPMap {
					if allowedPrefix.Contains(srcPrefix.Addr()) && allowedPrefix.Bits() < srcPrefix.Bits() {
						return fmt.Errorf("[Strict-Bind Audit] Rule[%d] Src %s is broad-matched by Peer %s (AllowedIPs: %s). Possible IP Spoofing risk.", 
							i, srcPrefix.String(), pk[:8], allowedPrefix.String())
					}
				}
				// If not found at all, it might be an external IP or misconfigured
				continue 
			}
			
			_ = pubKey // Found exact match, audit passed for this prefix
		}
	}

	return nil
}
