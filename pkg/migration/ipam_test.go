package migration

import (
	"net/netip"
	"testing"
)

func TestPlanIPs(t *testing.T) {
	cidr := netip.MustParsePrefix("10.50.0.0/24")
	plan, err := PlanIPs(cidr, 2)
	if err != nil {
		t.Fatalf("PlanIPs returned error: %v", err)
	}
	if plan.ServerIP.String() != "10.50.0.1" {
		t.Fatalf("expected server ip 10.50.0.1, got %s", plan.ServerIP.String())
	}
	if len(plan.ClientIPs) != 2 {
		t.Fatalf("expected 2 client ips, got %d", len(plan.ClientIPs))
	}
	if plan.ClientIPs[0].String() != "10.50.0.2" || plan.ClientIPs[1].String() != "10.50.0.3" {
		t.Fatalf("unexpected client ips: %v", plan.ClientIPs)
	}
}

func TestPlanIPsTooSmall(t *testing.T) {
	cidr := netip.MustParsePrefix("10.50.0.0/31")
	if _, err := PlanIPs(cidr, 0); err == nil {
		t.Fatalf("expected error for /31")
	}
}
