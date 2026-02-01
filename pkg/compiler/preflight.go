package compiler

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
)

type ConflictReport struct {
	HasFirewalld  bool
	HasUFW        bool
	HasDocker     bool
	NonWPCTables  []string
}

func PreflightConflicts() (*ConflictReport, error) {
	c := &nftables.Conn{}
	tables, err := c.ListTables()
	if err != nil {
		return nil, err
	}

	chains, err := c.ListChains()
	if err != nil {
		return nil, err
	}

	cr := &ConflictReport{}

	for _, t := range tables {
		fam := familyName(t.Family)
		name := t.Name
		if fam == "inet" && name == "firewalld" {
			cr.HasFirewalld = true
		}
		if !strings.HasPrefix(name, "wpc_") {
			cr.NonWPCTables = append(cr.NonWPCTables, fmt.Sprintf("%s/%s", fam, name))
		}
	}

	for _, ch := range chains {
		table := ch.Table
		if table == nil {
			continue
		}
		tname := table.Name
		cname := ch.Name
		if cname == "DOCKER-USER" {
			cr.HasDocker = true
		}
		if strings.HasPrefix(cname, "ufw-") || tname == "ufw" {
			cr.HasUFW = true
		}
	}

	return cr, nil
}

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return "unknown"
	}
}
