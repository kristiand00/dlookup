package lookup_test

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"dlookup/lookup"

	"github.com/miekg/dns"
)

// zoneServer is a small authoritative test server for one zone, on UDP and TCP.
type zoneServer struct {
	zone      string
	records   []dns.RR
	allowAXFR bool

	mu      sync.Mutex
	queries int
}

// startZoneServer serves zone (records in zone-file syntax) on 127.0.0.1 and
// returns its "host:port" address.
func startZoneServer(t *testing.T, zone string, allowAXFR bool, records ...string) (string, *zoneServer) {
	t.Helper()
	zs := &zoneServer{zone: dns.Fqdn(zone), allowAXFR: allowAXFR}
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil {
			t.Fatalf("bad test RR %q: %v", r, err)
		}
		zs.records = append(zs.records, rr)
	}

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
	for _, srv := range []*dns.Server{
		{PacketConn: pc, Handler: zs},
		{Listener: tl, Handler: zs},
	} {
		var started sync.WaitGroup
		started.Add(1)
		srv.NotifyStartedFunc = started.Done
		go func() { _ = srv.ActivateAndServe() }()
		started.Wait()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return tl.Addr().String(), zs
}

func (zs *zoneServer) soa() dns.RR {
	for _, rr := range zs.records {
		if rr.Header().Rrtype == dns.TypeSOA {
			return rr
		}
	}
	return nil
}

func (zs *zoneServer) owned(name string) []dns.RR {
	var out []dns.RR
	for _, rr := range zs.records {
		if strings.EqualFold(rr.Header().Name, name) {
			out = append(out, rr)
		}
	}
	return out
}

func (zs *zoneServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	zs.mu.Lock()
	zs.queries++
	zs.mu.Unlock()

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if name != zs.zone && !strings.HasSuffix(name, "."+zs.zone) {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	if q.Qtype == dns.TypeAXFR {
		if !zs.allowAXFR {
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		soa := zs.soa()
		m.Answer = append([]dns.RR{soa}, zs.records...)
		m.Answer = append(m.Answer, soa)
		_ = w.WriteMsg(m)
		return
	}

	rrs := zs.owned(name)
	if len(rrs) == 0 {
		// Wildcard synthesis from "*.<parent>".
		if i := strings.Index(name, "."); i >= 0 && !zs.hasDescendant(name) {
			for _, rr := range zs.owned("*" + name[i:]) {
				c := dns.Copy(rr)
				c.Header().Name = q.Name
				rrs = append(rrs, c)
			}
		}
	}
	if len(rrs) == 0 && !zs.hasDescendant(name) {
		m.Rcode = dns.RcodeNameError
	}
	m.Answer = zs.answer(rrs, q.Qtype, 0)
	if len(m.Answer) == 0 {
		m.Ns = []dns.RR{zs.soa()}
	}
	_ = w.WriteMsg(m)
}

// answer returns rrs of qtype, following in-zone CNAMEs (like a real server
// would, which is what produces "chain noise").
func (zs *zoneServer) answer(rrs []dns.RR, qtype uint16, depth int) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			out = append(out, rr)
		} else if cn, ok := rr.(*dns.CNAME); ok && qtype != dns.TypeCNAME && depth < 5 {
			out = append(out, rr)
			out = append(out, zs.answer(zs.owned(cn.Target), qtype, depth+1)...)
		}
	}
	return out
}

func (zs *zoneServer) hasDescendant(name string) bool {
	for _, rr := range zs.records {
		if strings.HasSuffix(strings.ToLower(rr.Header().Name), "."+name) {
			return true
		}
	}
	return false
}

var oldZone = []string{
	"example.com. 300 IN SOA ns1.oldprov.net. hostmaster.example.com. 2024010101 7200 3600 1209600 300",
	"example.com. 300 IN NS ns1.oldprov.net.",
	"example.com. 300 IN NS ns2.oldprov.net.",
	"example.com. 300 IN A 192.0.2.1",
	"example.com. 300 IN MX 10 mail.example.com.",
	`example.com. 300 IN TXT "v=spf1 -all"`,
	"mail.example.com. 300 IN A 192.0.2.10",
	"www.example.com. 300 IN CNAME example.com.",
	"shop.example.com. 300 IN A 192.0.2.20",
	"blog.example.com. 300 IN A 192.0.2.30",
	`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`,
	"secret.example.com. 300 IN A 192.0.2.40",
	"app.example.com. 300 IN CNAME backend.example.com.",
	"backend.example.com. 300 IN A 192.0.2.50",
	"example.com. 300 IN RRSIG A 13 2 300 20250101000000 20240101000000 12345 example.com. AAAA",
}

var newZone = []string{
	"example.com. 300 IN SOA ns1.oldprov.net. hostmaster.example.com. 2024020202 7200 3600 1209600 300",
	"example.com. 300 IN NS ns1.newprov.net.",
	"example.com. 3600 IN A 192.0.2.1",
	"example.com. 300 IN MX 10 MAIL.example.com.",
	`example.com. 300 IN TXT "v=spf1 " "-all"`,
	"mail.example.com. 300 IN A 192.0.2.10",
	"www.example.com. 300 IN CNAME example.com.",
	"blog.example.com. 300 IN A 192.0.2.31",
	`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`,
	"secret.example.com. 300 IN A 192.0.2.40",
	"api.example.com. 300 IN A 192.0.2.60",
	"app.example.com. 300 IN CNAME backend.example.com.",
	"backend.example.com. 300 IN A 192.0.2.50",
}

func runDiff(t *testing.T, opts lookup.ZoneDiffOptions) *lookup.ZoneDiffResult {
	t.Helper()
	if opts.Domain == "" {
		opts.Domain = "example.com"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	res, err := lookup.DiffZone(context.Background(), opts)
	if err != nil {
		t.Fatalf("DiffZone: %v", err)
	}
	return res
}

func recordMap(res *lookup.ZoneDiffResult) map[string]lookup.RecordDiff {
	m := map[string]lookup.RecordDiff{}
	for _, r := range res.Records {
		m[r.Name+" "+r.Type] = r
	}
	return m
}

func expectStatus(t *testing.T, recs map[string]lookup.RecordDiff, key string, want lookup.DiffStatus) lookup.RecordDiff {
	t.Helper()
	r, ok := recs[key]
	if !ok {
		t.Errorf("%s: not reported, want %s", key, want)
		return r
	}
	if r.Status != want {
		t.Errorf("%s: status %s, want %s (old=%v new=%v err=%q)", key, r.Status, want, r.Old, r.New, r.Err)
	}
	return r
}

func TestDiffZoneProbe(t *testing.T) {
	oldAddr, _ := startZoneServer(t, "example.com", false, oldZone...)
	newAddr, _ := startZoneServer(t, "example.com", false, newZone...)

	var progressMu sync.Mutex
	progressCalls := 0
	res := runDiff(t, lookup.ZoneDiffOptions{
		OldServer: oldAddr, NewServer: newAddr, TryAXFR: true, Concurrency: 4,
		Progress: func(done, total int) {
			progressMu.Lock()
			progressCalls++
			progressMu.Unlock()
		},
	})
	if !strings.HasPrefix(res.Enumeration, "probe (") {
		t.Errorf("Enumeration = %q, want probe", res.Enumeration)
	}
	if res.NewServer != newAddr || len(res.OldServers) != 1 || res.OldServers[0] != oldAddr {
		t.Errorf("servers = %v / %s", res.OldServers, res.NewServer)
	}
	if progressCalls == 0 {
		t.Error("Progress never called")
	}
	recs := recordMap(res)
	expectStatus(t, recs, "example.com. A", lookup.DiffMatch) // TTL differs, ignored
	soa := expectStatus(t, recs, "example.com. SOA", lookup.DiffMatch)
	if !strings.Contains(soa.Note, "serial ignored") {
		t.Errorf("SOA note = %q", soa.Note)
	}
	ns := expectStatus(t, recs, "example.com. NS", lookup.DiffChanged)
	if !strings.Contains(ns.Note, "expected to differ") {
		t.Errorf("NS note = %q", ns.Note)
	}
	expectStatus(t, recs, "example.com. MX", lookup.DiffMatch)  // case-insensitive names
	expectStatus(t, recs, "example.com. TXT", lookup.DiffMatch) // chunking ignored
	expectStatus(t, recs, "mail.example.com. A", lookup.DiffMatch)
	expectStatus(t, recs, "www.example.com. CNAME", lookup.DiffMatch)
	expectStatus(t, recs, "app.example.com. CNAME", lookup.DiffMatch)
	expectStatus(t, recs, "backend.example.com. A", lookup.DiffMatch) // discovered via CNAME target
	expectStatus(t, recs, "shop.example.com. A", lookup.DiffMissing)
	blog := expectStatus(t, recs, "blog.example.com. A", lookup.DiffChanged)
	if len(blog.Old) != 1 || blog.Old[0] != "192.0.2.30" || len(blog.New) != 1 || blog.New[0] != "192.0.2.31" {
		t.Errorf("blog = %+v", blog)
	}
	expectStatus(t, recs, "api.example.com. A", lookup.DiffExtra)
	expectStatus(t, recs, "_dmarc.example.com. TXT", lookup.DiffMatch)

	// CNAME chains must not produce A/MX/... entries at the alias.
	for _, k := range []string{"www.example.com. A", "www.example.com. MX", "app.example.com. A"} {
		if _, ok := recs[k]; ok {
			t.Errorf("%s reported (CNAME chain noise)", k)
		}
	}
	// Not in the probe list.
	if _, ok := recs["secret.example.com. A"]; ok {
		t.Error("secret.example.com found without AXFR/ExtraNames")
	}
	if !res.HasDifferences() {
		t.Error("HasDifferences = false")
	}
	if res.Counts[lookup.DiffMissing] != 1 || res.Counts[lookup.DiffExtra] != 1 || res.Counts[lookup.DiffChanged] != 2 {
		t.Errorf("Counts = %v", res.Counts)
	}
	// Sorted: apex first.
	if res.Records[0].Name != "example.com." {
		t.Errorf("first record %s", res.Records[0].Name)
	}

	out := lookup.FormatZoneDiff(res, false)
	for _, want := range []string{
		"Zone diff for example.com.", "Summary:", "~ blog.example.com. A", "- old: 192.0.2.30", "+ new: 192.0.2.31",
		"- shop.example.com. A", "missing on new", "+ api.example.com. A", "extra on new",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatZoneDiff missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "= mail.example.com.") {
		t.Errorf("matches shown without showMatches:\n%s", out)
	}
	if !strings.Contains(lookup.FormatZoneDiff(res, true), "= mail.example.com. A") {
		t.Error("matches not shown with showMatches")
	}
}

func TestDiffZoneExtraNamesAndTTL(t *testing.T) {
	oldAddr, _ := startZoneServer(t, "example.com", false, oldZone...)
	newAddr, _ := startZoneServer(t, "example.com", false, newZone...)

	res := runDiff(t, lookup.ZoneDiffOptions{
		OldServer: oldAddr, NewServer: newAddr, CompareTTL: true,
		ExtraNames: []string{"secret", "nothere.example.com."},
		Types:      []uint16{dns.TypeA},
	})
	recs := recordMap(res)
	expectStatus(t, recs, "secret.example.com. A", lookup.DiffMatch)
	a := expectStatus(t, recs, "example.com. A", lookup.DiffChanged)
	if len(a.Old) != 1 || a.Old[0] != "192.0.2.1 ttl=300" || a.New[0] != "192.0.2.1 ttl=3600" {
		t.Errorf("TTL compare: %+v", a)
	}
	for _, r := range res.Records {
		if r.Type != "A" {
			t.Errorf("unexpected type %s with Types=[A]", r.Type)
		}
		if r.Name == "nothere.example.com." {
			t.Error("name absent on both sides was reported")
		}
	}
}

func TestDiffZoneAXFR(t *testing.T) {
	oldAddr, _ := startZoneServer(t, "example.com", true, oldZone...)
	newAddr, _ := startZoneServer(t, "example.com", false, newZone...)

	res := runDiff(t, lookup.ZoneDiffOptions{OldServer: oldAddr, NewServer: newAddr, TryAXFR: true})
	if res.Enumeration != "axfr from old" {
		t.Fatalf("Enumeration = %q", res.Enumeration)
	}
	recs := recordMap(res)
	expectStatus(t, recs, "secret.example.com. A", lookup.DiffMatch) // only found via AXFR
	expectStatus(t, recs, "shop.example.com. A", lookup.DiffMissing)
	for _, r := range res.Records {
		if r.Type == "RRSIG" {
			t.Error("RRSIG compared")
		}
	}

	// Same servers with TryAXFR off -> probe.
	res = runDiff(t, lookup.ZoneDiffOptions{OldServer: oldAddr, NewServer: newAddr})
	if !strings.HasPrefix(res.Enumeration, "probe") {
		t.Errorf("Enumeration = %q", res.Enumeration)
	}

	// Both allow -> merged.
	newAddr2, _ := startZoneServer(t, "example.com", true, newZone...)
	res = runDiff(t, lookup.ZoneDiffOptions{OldServer: oldAddr, NewServer: newAddr2, TryAXFR: true})
	if res.Enumeration != "axfr from old and new" {
		t.Errorf("Enumeration = %q", res.Enumeration)
	}
}

func TestDiffZoneIdenticalAndWildcard(t *testing.T) {
	zone := []string{
		"example.org. 300 IN SOA ns.example.org. h.example.org. 1 7200 3600 1209600 300",
		"example.org. 300 IN NS ns.example.org.",
		"ns.example.org. 300 IN A 192.0.2.53",
		"example.org. 300 IN A 192.0.2.1",
	}
	oldAddr, _ := startZoneServer(t, "example.org", false, zone...)
	newAddr, _ := startZoneServer(t, "example.org", false, zone...)
	res := runDiff(t, lookup.ZoneDiffOptions{Domain: "Example.ORG.", OldServer: oldAddr, NewServer: newAddr})
	if res.HasDifferences() {
		t.Errorf("identical zones differ:\n%s", lookup.FormatZoneDiff(res, true))
	}
	if !strings.Contains(lookup.FormatZoneDiff(res, false), "No differences found.") {
		t.Error("missing 'No differences found.'")
	}
	recs := recordMap(res)
	expectStatus(t, recs, "ns.example.org. A", lookup.DiffMatch) // discovered via NS target

	wild := append(append([]string(nil), zone...), "*.example.org. 300 IN A 192.0.2.99")
	newAddr2, _ := startZoneServer(t, "example.org", false, wild...)
	res = runDiff(t, lookup.ZoneDiffOptions{Domain: "example.org", OldServer: oldAddr, NewServer: newAddr2, Types: []uint16{dns.TypeA}})
	w := expectStatus(t, recordMap(res), "*.example.org. A", lookup.DiffExtra)
	if !strings.Contains(w.Note, "wildcard") {
		t.Errorf("wildcard note = %q", w.Note)
	}
}

func TestDiffZoneDiscoverOldServers(t *testing.T) {
	oldAddr, _ := startZoneServer(t, "example.com", false, oldZone...)
	newAddr, _ := startZoneServer(t, "example.com", false, newZone...)
	_, port, _ := net.SplitHostPort(oldAddr)

	var resolved []string
	var mu sync.Mutex
	restore := lookup.SetZoneDiffHooks([]string{oldAddr}, func(ctx context.Context, host string) ([]string, error) {
		mu.Lock()
		resolved = append(resolved, host)
		mu.Unlock()
		return []string{"127.0.0.1"}, nil
	}, port)
	defer restore()

	// "shop.example.com" has no NS of its own: the apex is found via SOA.
	res := runDiff(t, lookup.ZoneDiffOptions{Domain: "shop.example.com", NewServer: newAddr, Types: []uint16{dns.TypeA}})
	if len(res.OldServers) != 1 || res.OldServers[0] != "127.0.0.1:"+port {
		t.Errorf("OldServers = %v", res.OldServers)
	}
	if len(resolved) != 2 || resolved[0] != "ns1.oldprov.net" {
		t.Errorf("resolved NS hosts = %v", resolved)
	}
	expectStatus(t, recordMap(res), "shop.example.com. A", lookup.DiffMissing)

	// NewServer given as a hostname is resolved too.
	res = runDiff(t, lookup.ZoneDiffOptions{Domain: "example.com", NewServer: "ns.newprov.test:" + port, Types: []uint16{dns.TypeA}})
	if res.NewServer != "127.0.0.1:"+port {
		t.Errorf("NewServer = %q", res.NewServer)
	}
}

func TestDiffZoneErrors(t *testing.T) {
	oldAddr, _ := startZoneServer(t, "example.com", false, oldZone...)
	otherAddr, _ := startZoneServer(t, "example.net", false,
		"example.net. 300 IN SOA ns.example.net. h.example.net. 1 7200 3600 1209600 300")

	ctx := context.Background()
	cases := []lookup.ZoneDiffOptions{
		{Domain: "", NewServer: oldAddr},
		{Domain: "192.0.2.1", NewServer: oldAddr},
		{Domain: "example.com"},
		{Domain: "example.com", NewServer: "-bad"},
		{Domain: "example.com", NewServer: oldAddr, ExtraNames: []string{"bad name"}},
		// New server does not serve the zone (REFUSED).
		{Domain: "example.com", OldServer: oldAddr, NewServer: otherAddr, Timeout: time.Second},
	}
	for i, opts := range cases {
		if _, err := lookup.DiffZone(ctx, opts); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := lookup.DiffZone(cctx, lookup.ZoneDiffOptions{Domain: "example.com", OldServer: oldAddr, NewServer: oldAddr}); err == nil {
		t.Error("cancelled context: expected error")
	}
}

func TestDiffStatusJSON(t *testing.T) {
	r := &lookup.ZoneDiffResult{
		Domain:  "example.com.",
		Records: []lookup.RecordDiff{{Name: "example.com.", Type: "A", Status: lookup.DiffMissing, Old: []string{"192.0.2.1"}}},
		Counts:  map[lookup.DiffStatus]int{lookup.DiffMissing: 1},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"status":"missing"`) || !strings.Contains(s, `"counts":{"missing":1}`) {
		t.Errorf("JSON = %s", s)
	}
	var back lookup.ZoneDiffResult
	if err := json.Unmarshal(b, &back); err != nil || back.Records[0].Status != lookup.DiffMissing {
		t.Errorf("round trip: %v %+v", err, back)
	}
	for i, want := range []string{"match", "changed", "missing", "extra", "error"} {
		if got := lookup.DiffStatus(i).String(); got != want {
			t.Errorf("DiffStatus(%d) = %q", i, got)
		}
	}
}
