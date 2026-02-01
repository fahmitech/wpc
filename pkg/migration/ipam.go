package migration

import (
	"fmt"
	"net/netip"
)

type IPPlan struct {
	Network   netip.Prefix
	ServerIP  netip.Addr
	ClientIPs []netip.Addr
}

func PlanIPs(cidr netip.Prefix, clientCount int) (*IPPlan, error) {
	if clientCount < 0 {
		return nil, fmt.Errorf("clientCount must be >= 0")
	}
	if !cidr.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 CIDRs are supported for now")
	}
	if cidr.Bits() < 1 || cidr.Bits() > 30 {
		return nil, fmt.Errorf("CIDR %s is too small; need at least /30", cidr.String())
	}

	network := cidr.Masked()
	base := v4ToUint32(network.Addr())
	size := uint32(1) << uint32(32-network.Bits())

	firstUsable := base + 1
	lastUsable := base + size - 2
	if firstUsable > lastUsable {
		return nil, fmt.Errorf("CIDR %s has no usable host addresses", network.String())
	}

	if clientCount > int(^uint32(0)-1) {
		return nil, fmt.Errorf("clientCount %d exceeds maximum supported value", clientCount)
	}
	needed := uint32(1 + clientCount)
	available := (lastUsable - firstUsable) + 1
	if needed > available {
		return nil, fmt.Errorf("CIDR %s has %d usable addresses; need %d", network.String(), available, needed)
	}

	server := uint32ToV4(firstUsable)
	var clients []netip.Addr
	for i := 0; i < clientCount; i++ {
		clients = append(clients, uint32ToV4(firstUsable+uint32(i)+1))
	}

	return &IPPlan{
		Network:   network,
		ServerIP:  server,
		ClientIPs: clients,
	}, nil
}

func v4ToUint32(a netip.Addr) uint32 {
	v := a.As4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToV4(v uint32) netip.Addr {
	var b [4]byte
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
	return netip.AddrFrom4(b)
}
