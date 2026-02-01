package migration

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type OpenVPNSource struct {
	IndexTxtPath   string
	ServerConfPath string
}

func ParseOpenVPNIdentities(cfgPath string) ([]string, error) {
	lower := strings.ToLower(filepath.Base(cfgPath))
	switch lower {
	case "index.txt":
		return parseOpenVPNIndexTxt(cfgPath)
	case "server.conf":
		indexPath := filepath.Join(filepath.Dir(cfgPath), "index.txt")
		if _, err := os.Stat(indexPath); err == nil {
			return parseOpenVPNIndexTxt(indexPath)
		}
		return nil, fmt.Errorf("server.conf provided but %s not found; provide index.txt directly", indexPath)
	default:
		return nil, fmt.Errorf("unsupported OpenVPN config file %q (expected index.txt or server.conf)", cfgPath)
	}
}

func parseOpenVPNIndexTxt(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var out []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			continue
		}
		if fields[0] != "V" {
			continue
		}

		subject := fields[len(fields)-1]
		cn := extractOpenVPNCN(subject)
		if cn == "" {
			continue
		}
		if _, ok := seen[cn]; ok {
			continue
		}
		seen[cn] = struct{}{}
		out = append(out, cn)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no active identities found in %s", path)
	}
	return out, nil
}

func extractOpenVPNCN(subject string) string {
	if subject == "" {
		return ""
	}
	s := strings.TrimSpace(subject)
	if strings.Contains(s, "/CN=") {
		parts := strings.SplitN(s, "/CN=", 2)
		if len(parts) != 2 {
			return ""
		}
		rest := parts[1]
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			rest = rest[:idx]
		}
		return strings.TrimSpace(rest)
	}
	if strings.Contains(s, "CN=") {
		parts := strings.SplitN(s, "CN=", 2)
		if len(parts) != 2 {
			return ""
		}
		rest := parts[1]
		if idx := strings.IndexByte(rest, ','); idx >= 0 {
			rest = rest[:idx]
		}
		return strings.TrimSpace(rest)
	}
	if strings.Contains(s, "cn=") {
		parts := strings.SplitN(s, "cn=", 2)
		if len(parts) != 2 {
			return ""
		}
		rest := parts[1]
		if idx := strings.IndexByte(rest, ','); idx >= 0 {
			rest = rest[:idx]
		}
		return strings.TrimSpace(rest)
	}
	return ""
}
