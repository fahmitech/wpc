package types

import (
	"fmt"
	"net/netip"
)

// Policy represents the root configuration for WPC
type Policy struct {
	Version     string                `yaml:"version" json:"version"`
	Global      GlobalSettings        `yaml:"global" json:"global"`
	Definitions map[string]Definition `yaml:"definitions" json:"definitions"`
	Rules       []Rule                `yaml:"rules" json:"rules"`
}

// GlobalSettings contains compiler and sentinel configurations
type GlobalSettings struct {
	Interface        string   `yaml:"interface" json:"interface"`
	IPv6Mode         string   `yaml:"ipv6_mode" json:"ipv6_mode"`         // "allow" or "block"
	EgressPolicy     string   `yaml:"egress_policy" json:"egress_policy"` // "allow" or "block"
	DNSServers       []string `yaml:"dns_servers" json:"dns_servers"`
	AllowTunneling   bool     `yaml:"allow_tunneling" json:"allow_tunneling"`
	SentinelInterval int      `yaml:"sentinel_interval" json:"sentinel_interval"`
}

// Definition can be a single IP, CIDR, or a list (Group)
type Definition []string

// UnmarshalYAML implements custom unmarshaling to support both string and []string
func (d *Definition) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var single string
	if err := unmarshal(&single); err == nil {
		*d = []string{single}
		return nil
	}

	var slice []string
	if err := unmarshal(&slice); err == nil {
		*d = slice
		return nil
	}

	return fmt.Errorf("definition must be a string or a list of strings")
}

// Rule defines an Access Control List entry
type Rule struct {
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	Comment     string   `yaml:"comment,omitempty" json:"comment,omitempty"`
	Action      string   `yaml:"action" json:"action"`     // "accept", "drop"
	Protocol    string   `yaml:"proto" json:"proto"`       // "tcp", "udp", "icmp", "any"
	Source      []string `yaml:"src" json:"src"`           // Can be IP, CIDR, or Alias
	Destination []string `yaml:"dst" json:"dst"`           // Can be IP, CIDR, or Alias
	Port        string   `yaml:"port" json:"port"`         // "any", "80", "8000-8010"

	// Parsed fields for internal use
	SrcPrefixes []netip.Prefix `yaml:"-" json:"-"`
	DstPrefixes []netip.Prefix `yaml:"-" json:"-"`
}
