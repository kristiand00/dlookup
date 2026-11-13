package lookup

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDNS is a small DNS server for the health-check tests. With no zones it
// acts as a recursive resolver over all its records (RA set, CNAMEs chased);
// with zones it is authoritative for them (AA set, referrals at cuts).
type fakeDNS struct {
	addr      string
	zones     []string
	records   map[string][]dns.RR
	noAA      bool // authoritative mode: clear the AA bit (lame server)
	refuse    bool // answer REFUSED to everything
	recursion bool // authoritative mode: also answer other names recursively (open resolver)
	rcode     map[string]int

	mu      sync.Mutex
	queries int
}

func newFake(t *testing.T, zones []string, recs ...string) *fakeDNS {
	t.Helper()
	f := &fakeDNS{records: map[string][]dns.RR{}, rcode: map[string]int{}}
	for _, z := range zones {
		f.zones = append(f.zones, dns.Fqdn(strings.ToLower(z)))
	}
	f.add(t, recs...)
	f.start(t)
	return f
}

func (f *fakeDNS) add(t *testing.T, recs ...string) {
	t.Helper()
	for _, s := range recs {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("bad RR %q: %v", s, err)
		}
		f.addRR(rr)
	}
}

func (f *fakeDNS) addRR(rrs ...dns.RR) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rr := range rrs {
		k := strings.ToLower(rr.Header().Name)
		f.records[k] = append(f.records[k], rr)
	}
}

func (f *fakeDNS) start(t *testing.T) {
	t.Helper()
	var (
		tl  net.Listener
		pc  net.PacketConn
		err error
	)
	for i := 0; i < 20; i++ {
		tl, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		pc, err = net.ListenPacket("udp", tl.Addr().String())
		if err == nil {
			break
		}
		tl.Close()
	}
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: f}, {Listener: tl, Handler: f}} {
		var started sync.WaitGroup
		started.Add(1)
		srv.NotifyStartedFunc = started.Done
		go func() { _ = srv.ActivateAndServe() }()
		started.Wait()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	f.addr = tl.Addr().String()
}

func (f *fakeDNS) owned(name string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range f.records[name] {
		if rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

func (f *fakeDNS) sigs(name string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range f.records[name] {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == qtype {
			out = append(out, rr)
		}
	}
	return out
}

func (f *fakeDNS) exists(name string) bool {
	if len(f.records[name]) > 0 {
		return true
	}
	for k := range f.records {
		if strings.HasSuffix(k, "."+name) {
			return true
		}
	}
	return false
}

// soaFor returns the SOA of the closest enclosing apex present.
func (f *fakeDNS) soaFor(name string) []dns.RR {
	for n := name; ; {
		if soa := f.owned(n, dns.TypeSOA); len(soa) > 0 {
			return soa
		}
		i := strings.Index(n, ".")
		if i < 0 || n == "." || i == len(n)-1 {
			return nil
		}
		n = n[i+1:]
	}
}

func (f *fakeDNS) zoneFor(name string) string {
	best := ""
	for _, z := range f.zones {
		if dns.IsSubDomain(z, name) && len(z) > len(best) {
			best = z
		}
	}
	return best
}

func (f *fakeDNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries++
	m := new(dns.Msg)
	m.SetReply(req)
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	do := req.IsEdns0() != nil && req.IsEdns0().Do()
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(4096, do)
	}
	if f.refuse {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	if rc, ok := f.rcode[name]; ok {
		m.Rcode = rc
		_ = w.WriteMsg(m)
		return
	}

	zone := f.zoneFor(name)
	if len(f.zones) > 0 && zone == "" {
		if f.recursion && req.RecursionDesired {
			m.RecursionAvailable = true
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.99")})
		} else {
			m.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(m)
		return
	}
	if len(f.zones) == 0 {
		m.RecursionAvailable = true
	} else {
		// Referral at a zone cut below our zone (DS is answered by the parent).
		labels := dns.SplitDomainName(name)
		for i := len(labels) - 1; i >= 0; i-- {
			cut := strings.Join(labels[i:], ".") + "."
			if cut == zone || !dns.IsSubDomain(zone, cut) || cut == zone {
				continue
			}
			ns := f.owned(cut, dns.TypeNS)
			if len(ns) == 0 || (cut == name && q.Qtype == dns.TypeDS) {
				continue
			}
			m.Ns = append(m.Ns, ns...)
			for _, rr := range ns {
				host := strings.ToLower(rr.(*dns.NS).Ns)
				m.Extra = append(m.Extra, f.owned(host, dns.TypeA)...)
				m.Extra = append(m.Extra, f.owned(host, dns.TypeAAAA)...)
			}
			_ = w.WriteMsg(m)
			return
		}
		m.Authoritative = !f.noAA
	}

	cur := name
	for hops := 0; hops < 8; hops++ {
		ans := f.owned(cur, q.Qtype)
		if len(ans) > 0 {
			m.Answer = append(m.Answer, ans...)
			if do {
				m.Answer = append(m.Answer, f.sigs(cur, q.Qtype)...)
			}
			break
		}
		cn := f.owned(cur, dns.TypeCNAME)
		if len(cn) == 0 || q.Qtype == dns.TypeCNAME {
			if !f.exists(cur) {
				m.Rcode = dns.RcodeNameError
			}
			m.Ns = append(m.Ns, f.soaFor(cur)...)
			if do {
				for _, rrs := range f.records {
					for _, rr := range rrs {
						if t := rr.Header().Rrtype; t == dns.TypeNSEC || t == dns.TypeNSEC3 {
							m.Ns = append(m.Ns, rr)
						}
					}
				}
			}
			break
		}
		m.Answer = append(m.Answer, cn...)
		if len(f.zones) > 0 {
			break // authoritative servers do not chase CNAMEs
		}
		cur = strings.ToLower(cn[0].(*dns.CNAME).Target)
	}
	_ = w.WriteMsg(m)
}

// withDial maps fake nameserver IPs to local test servers; unknown IPs go to
// a closed port.
func withDial(t *testing.T, m map[string]*fakeDNS) {
	t.Helper()
	old := chkDialAddr
	chkDialAddr = func(ip string) string {
		if f, ok := m[ip]; ok {
			return f.addr
		}
		return "127.0.0.1:1"
	}
	t.Cleanup(func() { chkDialAddr = old })
}

func testOpts(resolver *fakeDNS) Options {
	return Options{Server: resolver.addr, Timeout: 2 * time.Second}
}

func mustContain(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q:\n%s", w, out)
		}
	}
}

func mustNotContain(t *testing.T, out string, nots ...string) {
	t.Helper()
	for _, w := range nots {
		if strings.Contains(out, w) {
			t.Errorf("output unexpectedly contains %q:\n%s", w, out)
		}
	}
}

// --- world: a parent zone "test." delegating "example.test." ---------------

// world is a resolver, a parent server and two child servers.
type world struct {
	resolver, parent, ns1, ns2 *fakeDNS
	opts                       Options
}

var parentRecords = []string{
	"test. 3600 IN SOA a.nic.test. hostmaster.nic.test. 1 7200 3600 1209600 3600",
	"test. 3600 IN NS a.nic.test.",
	"a.nic.test. 3600 IN A 192.0.2.53",
}

var childRecords = []string{
	"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2024010101 7200 3600 1209600 600",
	"example.test. 3600 IN NS ns1.example.test.",
	"example.test. 3600 IN NS ns2.example.net.",
	"ns1.example.test. 3600 IN A 198.51.100.1",
	"example.test. 300 IN A 192.0.2.10",
}

func newWorld(t *testing.T, delegation []string, child1, child2 []string) *world {
	t.Helper()
	if delegation == nil {
		delegation = []string{
			"example.test. 86400 IN NS ns1.example.test.",
			"example.test. 86400 IN NS ns2.example.net.",
			"ns1.example.test. 86400 IN A 198.51.100.1",
		}
	}
	if child1 == nil {
		child1 = childRecords
	}
	if child2 == nil {
		child2 = childRecords
	}
	w := &world{}
	w.parent = newFake(t, []string{"test."}, append(append([]string(nil), parentRecords...), delegation...)...)
	w.ns1 = newFake(t, []string{"example.test."}, child1...)
	w.ns2 = newFake(t, []string{"example.test."}, child2...)
	// The resolver's view: the parent zone, the child zone and the hosts.
	var all []string
	all = append(all, parentRecords...)
	all = append(all, child1...)
	all = append(all, "ns2.example.net. 3600 IN A 203.0.113.2")
	w.resolver = newFake(t, nil, all...)
	withDial(t, map[string]*fakeDNS{"192.0.2.53": w.parent, "198.51.100.1": w.ns1, "203.0.113.2": w.ns2})
	w.opts = testOpts(w.resolver)
	return w
}

func TestChkReportSummary(t *testing.T) {
	var r chkReport
	r.line("Title")
	r.section("Checks:")
	r.ok("a")
	r.warn("b")
	r.bad("c")
	r.bad("d")
	r.info("e")
	got := r.String()
	want := "Title\n\nChecks:\n  ✓ a\n  ! b\n  ✗ c\n  ✗ d\n  - e\n\n1 ok, 1 warning, 2 problems"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestChkDuration(t *testing.T) {
	for in, want := range map[uint32]string{0: "0s", 59: "59s", 300: "5m", 3600: "1h", 5400: "1h30m", 86400: "1d", 172800: "2d", 90061: "1d1h1m1s"} {
		if got := chkDuration(in); got != want {
			t.Errorf("chkDuration(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestChkZoneAndReferral(t *testing.T) {
	w := newWorld(t, nil, nil, nil)
	ctx := context.Background()
	zone, err := chkZoneOf(ctx, w.opts, "www.example.test.")
	if err != nil || zone != "example.test." {
		t.Fatalf("chkZoneOf = %q, %v", zone, err)
	}
	ref := chkGetReferral(ctx, w.opts, "example.test.")
	if ref.Err != nil {
		t.Fatalf("referral: %v", ref.Err)
	}
	if ref.Parent != "test." || ref.NSTTL != 86400 || strings.Join(ref.NS, " ") != "ns1.example.test. ns2.example.net." {
		t.Errorf("referral = %+v", ref)
	}
	if g := ref.Glue["ns1.example.test."]; len(g) != 1 || g[0] != "198.51.100.1" {
		t.Errorf("glue = %v", ref.Glue)
	}
}

func TestDomainOnlyRejectsIP(t *testing.T) {
	for _, p := range []LookupProvider{&PropagationProvider{}, &DelegationProvider{}, &EmailProvider{}, &TakeoverProvider{}, &DNSSECProvider{}, &TTLPlanProvider{}} {
		_, err := p.Execute(context.Background(), "192.0.2.1", Options{})
		if err == nil || !strings.Contains(err.Error(), "needs a domain name") {
			t.Errorf("%s: err = %v, want domain-name error", p.Name(), err)
		}
		if _, err := p.Execute(context.Background(), "-bad", Options{}); err == nil {
			t.Errorf("%s: invalid target accepted", p.Name())
		}
		if !domainOnly(p) {
			t.Errorf("%s should be DomainOnly", p.Name())
		}
	}
}

func TestChecksContextCancel(t *testing.T) {
	w := newWorld(t, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, p := range []LookupProvider{&PropagationProvider{}, &DelegationProvider{}, &EmailProvider{}, &TakeoverProvider{}, &DNSSECProvider{}, &TTLPlanProvider{}} {
		if _, err := p.Execute(ctx, "example.test", w.opts); err == nil {
			t.Errorf("%s: no error for cancelled context", p.Name())
		}
	}
}

func TestReportRegistration(t *testing.T) {
	order := strings.Join(GetComprehensiveReportOrder(), ",")
	for _, n := range []string{"Delegation", "Email", "DNSSEC"} {
		p, ok := GetProvider(n)
		if !ok || excludedFromReport(p) || !strings.Contains(order, n) {
			t.Errorf("%s should be in the Report", n)
		}
	}
	for _, n := range []string{"Propagation", "Takeover", "TTL plan"} {
		p, ok := GetProvider(n)
		if !ok || !excludedFromReport(p) {
			t.Errorf("%s should be excluded from the Report", n)
		}
	}
	for _, f := range []string{"propagation", "delegation", "email", "takeover", "dnssec-check", "ttlplan"} {
		if _, ok := GetProviderByFlagName(f); !ok {
			t.Errorf("flag %s not registered", f)
		}
	}
}

func TestChkShortErr(t *testing.T) {
	for in, want := range map[string]string{
		"8.26.56.26:53: read udp 10.0.0.1:5->8.26.56.26:53: i/o timeout": "timeout",
		"context deadline exceeded":                                      "timeout",
		"read udp 127.0.0.1:1: connection refused":                       "connection refused",
		"SERVFAIL": "SERVFAIL",
	} {
		if got := chkShortErr(in); got != want {
			t.Errorf("chkShortErr(%q) = %q, want %q", in, got, want)
		}
	}
}
