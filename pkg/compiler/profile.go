package compiler

import (
	"fmt"

	"github.com/fahmitech/wpc/pkg/types"
)

func SelectProfile(policy *types.Policy, profile string) (*types.Policy, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}
	if len(policy.Profiles) == 0 {
		return policy, nil
	}

	name := profile
	if name == "" {
		if _, ok := policy.Profiles["default"]; ok {
			name = "default"
		} else {
			return nil, fmt.Errorf("policy has profiles; specify --profile (e.g. app or db)")
		}
	}
	p, ok := policy.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", name)
	}

	out := *policy
	out.Rules = p.Rules
	out.Profiles = nil
	return &out, nil
}

