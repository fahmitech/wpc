package sentinel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"io"
	"os"
	"os/exec"
	"time"
)

type State struct {
	ExpectedHash string `json:"expected_hash"`
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
		exec.Command("sudo", "nft", "-f", "/etc/nftables.conf").Run()
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
