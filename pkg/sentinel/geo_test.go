package sentinel

import "testing"

func TestParseCIDRList_IPv4(t *testing.T) {
	body := []byte(`
# comment
10.0.0.0/8
2001:db8::/32
10.0.0.0/8
invalid
`)
	out, err := parseCIDRList(body, 4)
	if err != nil {
		t.Fatalf("parseCIDRList error: %v", err)
	}
	if len(out) != 1 || out[0] != "10.0.0.0/8" {
		t.Fatalf("unexpected result: %v", out)
	}
}

func TestParseCIDRList_IPv6(t *testing.T) {
	body := []byte(`
2001:db8::/32
10.0.0.0/8
`)
	out, err := parseCIDRList(body, 6)
	if err != nil {
		t.Fatalf("parseCIDRList error: %v", err)
	}
	if len(out) != 1 || out[0] != "2001:db8::/32" {
		t.Fatalf("unexpected result: %v", out)
	}
}

