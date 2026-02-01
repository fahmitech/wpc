package migration

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func renderServerWGConfig(serverPrivBase64 string, ipPlan *IPPlan, listenPort int, clientKeys map[string]*Keypair, peerIPs map[string]netip.Addr) (string, error) {
	if serverPrivBase64 == "" {
		return "", fmt.Errorf("missing server private key")
	}
	if listenPort <= 0 || listenPort > 65535 {
		return "", fmt.Errorf("invalid listen port %d", listenPort)
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", serverPrivBase64))
	sb.WriteString(fmt.Sprintf("Address = %s/%d\n", ipPlan.ServerIP.String(), ipPlan.Network.Bits()))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", listenPort))
	sb.WriteString("\n")

	names := make([]string, 0, len(clientKeys))
	for n := range clientKeys {
		names = append(names, n)
	}
	sort.Strings(names)

	for i, name := range names {
		kp := clientKeys[name]
		ip := peerIPs[name]
		if kp == nil {
			return "", fmt.Errorf("missing keypair for %s", name)
		}
		if !ip.IsValid() {
			return "", fmt.Errorf("missing ip for %s", name)
		}

		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", kp.PublicKeyBase64))
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s/32\n", ip.String()))
	}

	sb.WriteString("\n")
	return sb.String(), nil
}

func renderClientWGConfig(clientPrivBase64 string, clientIP netip.Addr, serverPubBase64 string, endpointHostPort string, network netip.Prefix) (string, error) {
	if clientPrivBase64 == "" {
		return "", fmt.Errorf("missing client private key")
	}
	if !clientIP.IsValid() || !clientIP.Is4() {
		return "", fmt.Errorf("invalid client ip %s", clientIP.String())
	}
	if serverPubBase64 == "" {
		return "", fmt.Errorf("missing server public key")
	}
	if endpointHostPort == "" {
		return "", fmt.Errorf("missing endpoint")
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPrivBase64))
	sb.WriteString(fmt.Sprintf("Address = %s/32\n", clientIP.String()))
	sb.WriteString("\n")
	sb.WriteString("[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPubBase64))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", endpointHostPort))
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", network.String()))
	sb.WriteString("\n")
	return sb.String(), nil
}

func writeExport(outputDir string, force bool, wgServer string, policyJSON []byte, serverPubKey string, endpointHostPort string, ipPlan *IPPlan, clientKeys map[string]*Keypair, peerIPs map[string]netip.Addr) error {
	if outputDir == "" {
		return fmt.Errorf("missing output dir")
	}

	if st, err := os.Stat(outputDir); err == nil && st.IsDir() && !force {
		entries, err := os.ReadDir(outputDir)
		if err != nil {
			return fmt.Errorf("read output dir: %w", err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("output dir %s is not empty (use --force to overwrite)", outputDir)
		}
	}

	if force {
		_ = os.Remove(filepath.Join(outputDir, "wg0.conf"))
		_ = os.Remove(filepath.Join(outputDir, "policy.json"))
		_ = os.RemoveAll(filepath.Join(outputDir, "clients"))
	}

	if err := os.MkdirAll(filepath.Join(outputDir, "clients"), 0o700); err != nil {
		return fmt.Errorf("create export dir: %w", err)
	}

	wg0Path := filepath.Join(outputDir, "wg0.conf")
	if err := os.WriteFile(wg0Path, []byte(wgServer), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", wg0Path, err)
	}

	policyPath := filepath.Join(outputDir, "policy.json")
	if err := os.WriteFile(policyPath, policyJSON, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", policyPath, err)
	}

	names := make([]string, 0, len(clientKeys))
	for n := range clientKeys {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		kp := clientKeys[name]
		ip := peerIPs[name]
		cfg, err := renderClientWGConfig(kp.PrivateKeyBase64, ip, serverPubKey, endpointHostPort, ipPlan.Network)
		if err != nil {
			return err
		}
		outPath := filepath.Join(outputDir, "clients", name+".conf")
		if err := os.WriteFile(outPath, []byte(cfg), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
	}

	return nil
}

func normalizeEndpoint(endpoint string, defaultPort int) (string, int, error) {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return "", 0, fmt.Errorf("empty endpoint")
	}
	if defaultPort <= 0 || defaultPort > 65535 {
		return "", 0, fmt.Errorf("invalid port %d", defaultPort)
	}

	if strings.HasPrefix(ep, "[") {
		if host, portStr, err := net.SplitHostPort(ep); err == nil {
			p, err := strconv.Atoi(portStr)
			if err != nil || p <= 0 || p > 65535 {
				return "", 0, fmt.Errorf("invalid endpoint port %q", portStr)
			}
			return net.JoinHostPort(host, portStr), p, nil
		}
		if strings.HasSuffix(ep, "]") {
			host := strings.TrimPrefix(ep, "[")
			host = strings.TrimSuffix(host, "]")
			return net.JoinHostPort(host, strconv.Itoa(defaultPort)), defaultPort, nil
		}
		return "", 0, fmt.Errorf("invalid bracketed endpoint %q", endpoint)
	}

	if host, portStr, err := net.SplitHostPort(ep); err == nil {
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, fmt.Errorf("invalid endpoint port %q", portStr)
		}
		return net.JoinHostPort(host, portStr), p, nil
	}

	if strings.Count(ep, ":") >= 2 {
		return net.JoinHostPort(ep, strconv.Itoa(defaultPort)), defaultPort, nil
	}

	return net.JoinHostPort(ep, strconv.Itoa(defaultPort)), defaultPort, nil
}
