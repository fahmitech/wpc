package compiler

import (
	"testing"

	"github.com/fahmitech/wpc/pkg/types"
)

func TestSelectProfile_SelectsRules(t *testing.T) {
	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface:      "wg0",
			IPv6Mode:       "allow",
			EgressPolicy:   "allow",
			AllowTunneling: true,
		},
		Definitions: map[string]types.Definition{
			"admins": {"10.0.0.0/8"},
			"db":     {"10.100.0.20/32"},
		},
		Profiles: map[string]types.Profile{
			"app": {
				Rules: []types.Rule{
					{Name: "ssh", Action: "accept", Protocol: "tcp", Port: "22", Source: []string{"admins"}, Destination: []string{"any"}},
				},
			},
			"db": {
				Rules: []types.Rule{
					{Name: "db-only", Action: "drop", Protocol: "tcp", Port: "5432", Source: []string{"any"}, Destination: []string{"db"}},
				},
			},
		},
	}

	selected, err := SelectProfile(policy, "db")
	if err != nil {
		t.Fatalf("SelectProfile error: %v", err)
	}
	if len(selected.Rules) != 1 || selected.Rules[0].Name != "db-only" {
		t.Fatalf("unexpected rules: %+v", selected.Rules)
	}
	if err := ParseAndValidate(selected); err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
}

func TestSelectProfile_DefaultRequiresExplicitWithoutDefault(t *testing.T) {
	policy := &types.Policy{
		Version: "v2",
		Global: types.GlobalSettings{
			Interface: "wg0",
		},
		Definitions: map[string]types.Definition{},
		Profiles: map[string]types.Profile{
			"app": {Rules: []types.Rule{}},
		},
	}
	if _, err := SelectProfile(policy, ""); err == nil {
		t.Fatalf("expected error")
	}
}

