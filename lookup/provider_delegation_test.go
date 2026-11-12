package lookup

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// set changes a running fake server's behaviour safely.
func (f *fakeDNS) set(fn func(f *fakeDNS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func runDelegation(t *testing.T, w *world, target string) string {
	t.Helper()
	out, err := (&DelegationProvider{}).Execute(context.Background(), target, w.opts)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return out
}

func TestDelegationHealthy(t *testing.T) {
	w := newWorld(t, nil, nil, nil)
	out := runDelegation(t, w, "example.test")
	mustContain(t, out,
		"Delegation of example.test (parent zone test)",
		"Parent test referral from a.nic.test (192.0.2.53), NS TTL 86400 (1d)",
		"✓ parent test delegates example.test to 2 nameservers",
		"✓ all 2 nameserver addresses answer authoritatively",
		"✓ parent and child NS sets match",
		"✓ SOA serial 2024010101 on all nameservers",
		"✓ glue present and matching for 1 in-bailiwick nameserver",
		"✓ nameservers spread over 2 /24 networks",
		"✓ no open recursion",
		", 0 warnings, 0 problems",
	)
	// A name inside the zone checks the zone.
	out = runDelegation(t, w, "www.example.test")
	mustContain(t, out, "www.example.test is not a zone apex; checking its zone example.test")
}

func TestDelegationMismatchAndLame(t *testing.T) {
	child1 := append(append([]string(nil), childRecords...), "example.test. 3600 IN NS ns3.example.net.")
	w := newWorld(t, nil, child1, nil)
	w.ns2.set(func(f *fakeDNS) { f.noAA = true })
	out := runDelegation(t, w, "example.test")
	mustContain(t, out,
		"! parent and child NS sets differ",
		"ns1.example.test.: extra ns3.example.net.",
		"✗ lame delegation: not authoritative for example.test: ns2.example.net. 203.0.113.2",
		"NOT authoritative (lame)",
	)

	w.ns2.set(func(f *fakeDNS) { f.noAA = false; f.refuse = true })
	out = runDelegation(t, w, "example.test")
	mustContain(t, out, "✗ nameservers not answering: ns2.example.net. 203.0.113.2 (REFUSED)")
}

func TestDelegationGlueSerialRecursion(t *testing.T) {
	child2 := []string{
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2024010100 7200 3600 1209600 600",
		"example.test. 3600 IN NS ns1.example.test.",
		"example.test. 3600 IN NS ns2.example.net.",
		"ns1.example.test. 3600 IN A 198.51.100.1",
	}
	badGlue := []string{
		"example.test. 86400 IN NS ns1.example.test.",
		"example.test. 86400 IN NS ns2.example.net.",
		"ns1.example.test. 86400 IN A 198.51.100.9",
	}
	w := newWorld(t, badGlue, nil, child2)
	w.ns1.set(func(f *fakeDNS) { f.recursion = true })
	out := runDelegation(t, w, "example.test")
	mustContain(t, out,
		"✗ glue for ns1.example.test. (198.51.100.9) does not match the zone (198.51.100.1)",
		"! SOA serials differ",
		"2024010101: ns1.example.test.",
		"2024010100: ns2.example.net.",
		"! authoritative servers also answer recursive queries (open resolver, abuse risk): ns1.example.test. 198.51.100.1",
	)

	noGlue := []string{
		"example.test. 86400 IN NS ns1.example.test.",
		"example.test. 86400 IN NS ns2.example.net.",
	}
	w = newWorld(t, noGlue, nil, nil)
	out = runDelegation(t, w, "example.test")
	mustContain(t, out, "✗ missing glue for in-bailiwick nameserver ns1.example.test.")
}

func TestDelegationSingleNS(t *testing.T) {
	deleg := []string{"example.test. 86400 IN NS ns1.example.test.", "ns1.example.test. 86400 IN A 198.51.100.1"}
	child := []string{
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 600",
		"example.test. 3600 IN NS ns1.example.test.",
		"ns1.example.test. 3600 IN A 198.51.100.1",
	}
	w := newWorld(t, deleg, child, child)
	out := runDelegation(t, w, "example.test")
	mustContain(t, out, "✗ only 1 nameserver (at least 2 are required")
}

func TestDelegationSameNetworkAndUnresolvable(t *testing.T) {
	deleg := []string{
		"example.test. 86400 IN NS ns1.example.test.",
		"example.test. 86400 IN NS ns2.example.test.",
		"example.test. 86400 IN NS ns3.example.test.",
		"ns1.example.test. 86400 IN A 198.51.100.1",
		"ns2.example.test. 86400 IN A 198.51.100.2",
	}
	child := []string{
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 600",
		"example.test. 3600 IN NS ns1.example.test.",
		"example.test. 3600 IN NS ns2.example.test.",
		"example.test. 3600 IN NS ns3.example.test.",
		"ns1.example.test. 3600 IN A 198.51.100.1",
		"ns2.example.test. 3600 IN A 198.51.100.2",
		"ns3.example.test. 3600 IN CNAME ns1.example.test.",
	}
	w := newWorld(t, deleg, child, child)
	withDial(t, map[string]*fakeDNS{"192.0.2.53": w.parent, "198.51.100.1": w.ns1, "198.51.100.2": w.ns2})
	out := runDelegation(t, w, "example.test")
	mustContain(t, out,
		"! all IPv4 nameserver addresses are in one /24 network (198.51.100.0/24)",
		"✗ nameserver names are CNAMEs (not allowed, RFC 2181 §10.3): ns3.example.test. → ns1.example.test.",
		"✗ missing glue for in-bailiwick nameserver ns3.example.test.",
	)
}

func TestDelegationNXDomain(t *testing.T) {
	w := newWorld(t, nil, nil, nil)
	out := runDelegation(t, w, "nope.invalid")
	mustContain(t, out, "✗ nope.invalid. does not exist (NXDOMAIN)", "0 ok, 0 warnings, 1 problem")
}

func TestDelegSetDiff(t *testing.T) {
	got := delegSetDiff([]string{"a.", "b."}, []string{"b.", "c."})
	if got != "missing a., extra c." {
		t.Errorf("got %q", got)
	}
	if got := delegSetDiff([]string{"a."}, nil); got != "no NS records" {
		t.Errorf("got %q", got)
	}
	_ = dns.TypeNS
	_ = strings.TrimSpace
}
