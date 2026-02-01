package sentinel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type State struct {
	ExpectedHash string `json:"expected_hash"`
	GeoLast      map[string]int64 `json:"geo_last,omitempty"`
}

type Sentinel struct {
	Interval time.Duration
	StatePath string
}

func New(intervalSec int) *Sentinel {
	if intervalSec <= 0 {
		intervalSec = 15
	}
	return &Sentinel{
		Interval: time.Duration(intervalSec) * time.Second,
		StatePath: "/etc/wpc/state.json",
	}
}

func (s *Sentinel) Start(ctx context.Context) {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.EnforceIntegrity()
			s.UpdateDNS()
			s.UpdateGeo()
			s.CheckDockerDrift()
		}
	}
}

func (s *Sentinel) EnforceIntegrity() {
	curr := s.currentRulesHash()
	st := s.readState()
	if st.ExpectedHash == "" {
		st.ExpectedHash = curr
		s.writeState(st)
		return
	}
	if curr != st.ExpectedHash {
		if exec.Command("sudo", "nft", "-c", "-f", "/etc/nftables.conf").Run() == nil {
			exec.Command("sudo", "nft", "-f", "/etc/nftables.conf").Run()
		}
	}
}

func (s *Sentinel) CheckDockerDrift() {
	_ = exec.Command("sudo", "nft", "list", "chain", "ip", "filter", "DOCKER-USER").Run()
	_ = exec.Command("sudo", "nft", "insert", "rule", "ip", "filter", "DOCKER-USER", "jump", "inet", "wpc_filter", "input").Run()
}

func (s *Sentinel) currentRulesHash() string {
	cmd := exec.Command("sudo", "nft", "list", "ruleset")
	stdout, _ := cmd.StdoutPipe()
	_ = cmd.Start()
	h := sha256.New()
	io.Copy(h, stdout)
	cmd.Wait()
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Sentinel) readState() State {
	f, err := os.Open(s.StatePath)
	if err != nil {
		return State{}
	}
	defer f.Close()
	var st State
	json.NewDecoder(f).Decode(&st)
	return st
}

func (s *Sentinel) writeState(st State) {
	_ = os.MkdirAll("/etc/wpc", 0755)
	f, err := os.Create(s.StatePath)
	if err != nil {
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(st)
}

type dnsSet struct {
	Table  string   `json:"table"`
	Family string   `json:"family"`
	Name   string   `json:"name"`
	Hosts  []string `json:"hosts"`
}

type dnsConfig struct {
	Sets []dnsSet `json:"sets"`
}

func (s *Sentinel) UpdateDNS() {
	cfg := s.readDNSConfig()
	if len(cfg.Sets) == 0 {
		return
	}
	for _, set := range cfg.Sets {
		ips := s.resolveHosts(set.Hosts)
		if len(ips) == 0 {
			continue
		}
		_ = exec.Command("sudo", "nft", "flush", "set", set.Family, set.Table, set.Name).Run()
		args := []string{"nft", "add", "element", set.Family, set.Table, set.Name, "{"}
		for i, ip := range ips {
			args = append(args, ip)
			if i < len(ips)-1 {
				args = append(args, ",")
			}
		}
		args = append(args, "}")
		_ = exec.Command("sudo", args...).Run()
	}
}

type geoSet struct {
	Table      string `json:"table"`
	Family     string `json:"family"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	IPVersion  int    `json:"ip_version"`
	SHA256     string `json:"sha256,omitempty"`
	RefreshSec int    `json:"refresh_sec,omitempty"`
}

type geoConfig struct {
	Sets []geoSet `json:"sets"`
}

func (s *Sentinel) UpdateGeo() {
	cfg := s.readGeoConfig()
	if len(cfg.Sets) == 0 {
		return
	}

	st := s.readState()
	if st.GeoLast == nil {
		st.GeoLast = map[string]int64{}
	}

	now := time.Now().Unix()
	changed := false
	for _, set := range cfg.Sets {
		refresh := set.RefreshSec
		if refresh <= 0 {
			refresh = 86400
		}
		key := set.Family + "|" + set.Table + "|" + set.Name + "|" + set.URL
		if last, ok := st.GeoLast[key]; ok {
			if now-last < int64(refresh) {
				continue
			}
		}
		entries, err := s.fetchGeoCIDRs(set.URL, set.SHA256, set.IPVersion)
		if err != nil || len(entries) == 0 {
			continue
		}
		if err := s.updateSetElements(set.Family, set.Table, set.Name, entries); err != nil {
			continue
		}
		st.GeoLast[key] = now
		changed = true
	}
	if changed {
		s.writeState(st)
	}
}

func (s *Sentinel) readGeoConfig() geoConfig {
	f, err := os.Open("/etc/wpc/geo.json")
	if err != nil {
		return geoConfig{}
	}
	defer f.Close()
	var cfg geoConfig
	json.NewDecoder(f).Decode(&cfg)
	return cfg
}

func (s *Sentinel) fetchGeoCIDRs(feedURL string, expectedSHA256 string, ipVersion int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wpc-sentinel/1.0")
	req.Header.Set("Accept", "text/plain, */*")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("geo feed http status %d", resp.StatusCode)
	}

	const maxBytes = 20 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	if expectedSHA256 != "" {
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		want := strings.ToLower(strings.TrimSpace(expectedSHA256))
		if got != want {
			return nil, errors.New("geo feed sha256 mismatch")
		}
	}
	return parseCIDRList(body, ipVersion)
}

func parseCIDRList(body []byte, ipVersion int) ([]string, error) {
	if ipVersion != 4 && ipVersion != 6 {
		return nil, fmt.Errorf("invalid ip_version %d", ipVersion)
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	seen := map[string]struct{}{}
	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		pfx, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		if ipVersion == 4 && pfx.Addr().Is6() {
			continue
		}
		if ipVersion == 6 && !pfx.Addr().Is6() {
			continue
		}
		s := pfx.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no cidrs parsed")
	}
	return out, nil
}

func (s *Sentinel) updateSetElements(family string, table string, name string, elements []string) error {
	const maxPerChunk = 2000
	if len(elements) == 0 {
		return errors.New("no elements")
	}

	var chunks [][]string
	for i := 0; i < len(elements); i += maxPerChunk {
		j := i + maxPerChunk
		if j > len(elements) {
			j = len(elements)
		}
		chunks = append(chunks, elements[i:j])
	}

	first := true
	for _, chunk := range chunks {
		var sb strings.Builder
		if first {
			sb.WriteString(fmt.Sprintf("flush set %s %s %s\n", family, table, name))
		}
		sb.WriteString(fmt.Sprintf("add element %s %s %s { ", family, table, name))
		for i, el := range chunk {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(el)
		}
		sb.WriteString(" }\n")

		cmd := exec.Command("sudo", "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(sb.String())
		if err := cmd.Run(); err != nil {
			return err
		}
		first = false
	}
	return nil
}

func (s *Sentinel) readDNSConfig() dnsConfig {
	f, err := os.Open("/etc/wpc/dns.json")
	if err != nil {
		return dnsConfig{}
	}
	defer f.Close()
	var cfg dnsConfig
	json.NewDecoder(f).Decode(&cfg)
	return cfg
}

func (s *Sentinel) resolveHosts(hosts []string) []string {
	var ips []string
	for _, h := range hosts {
		as, err := net.LookupIP(h)
		if err != nil {
			continue
		}
		for _, a := range as {
			if a.To4() != nil {
				ips = append(ips, a.String())
			}
		}
	}
	return ips
}
