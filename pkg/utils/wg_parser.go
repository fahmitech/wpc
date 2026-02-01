package utils

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

type WGPeer struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
}

type WGConfig struct {
	InterfaceName string
	Peers         []WGPeer
}

// ParseWGConfig reads a standard wg.conf file and extracts peer information
func ParseWGConfig(path string) (*WGConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &WGConfig{}
	var currentPeer *WGPeer

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.EqualFold(line, "[Peer]") {
			if currentPeer != nil {
				config.Peers = append(config.Peers, *currentPeer)
			}
			currentPeer = &WGPeer{}
			continue
		}

		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			if currentPeer != nil {
				switch strings.ToLower(key) {
				case "publickey":
					currentPeer.PublicKey = val
				case "allowedips":
					ips := strings.Split(val, ",")
					for _, ipStr := range ips {
						p, err := netip.ParsePrefix(strings.TrimSpace(ipStr))
						if err == nil {
							currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, p)
						}
					}
				}
			}
		}
	}

	if currentPeer != nil {
		config.Peers = append(config.Peers, *currentPeer)
	}

	return config, nil
}
