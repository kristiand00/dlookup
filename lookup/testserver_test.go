package lookup_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"dlookup/lookup"

	"github.com/miekg/dns"
)

// testZone is served by startDNSServer. Names not listed get NXDOMAIN
// (unless they are under example.com, which gets NOERROR/NODATA).
var testZone = []string{
	"example.com. 300 IN A 192.0.2.1",
	"example.com. 300 IN AAAA 2001:db8::1",
	"example.com. 300 IN MX 10 mail.example.com.",
	"example.com. 300 IN NS ns1.example.com.",
	"example.com. 300 IN NS ns2.example.com.",
	"example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300",
	`example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
	`example.com. 300 IN TXT "v=spf1 include:_spf.example.net -all"`,
	`example.com. 300 IN TXT "google-site-verification=abc"`,
	`example.com. 300 IN TXT "v=spf10 not-really"`,
	`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`,
	`_dmarc.example.com. 300 IN TXT "unrelated"`,
	"www.example.com. 300 IN CNAME example.com.",
	"1.2.0.192.in-addr.arpa. 300 IN PTR host.example.com.",
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. 300 IN PTR host6.example.com.",
}

// startDNSServer runs an authoritative-ish test DNS server on 127.0.0.1 (UDP)
// and returns its "host:port" address.
func startDNSServer(t *testing.T) string {
	t.Helper()
	records := map[string][]dns.RR{}
	for _, z := range testZone {
		rr, err := dns.NewRR(z)
		if err != nil {
			t.Fatalf("bad test RR %q: %v", z, err)
		}
		key := strings.ToLower(rr.Header().Name)
		records[key] = append(records[key], rr)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if q.Qtype == dns.TypeANY {
			m.Rcode = dns.RcodeNotImplemented
			_ = w.WriteMsg(m)
			return
		}
		name := strings.ToLower(q.Name)
		rrs, ok := records[name]
		if !ok && !strings.HasSuffix(name, "example.com.") {
			m.Rcode = dns.RcodeNameError
		}
		for _, rr := range rrs {
			t := rr.Header().Rrtype
			if t == q.Qtype || (t == dns.TypeCNAME && q.Qtype != dns.TypeCNAME) {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var started sync.WaitGroup
	started.Add(1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: started.Done}
	go func() { _ = srv.ActivateAndServe() }()
	started.Wait()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// startRDAPServer serves the given path->JSON map plus IANA-style bootstrap
// files pointing back at itself, and points lookup.RDAPBootstrapBaseURL at it.
func startRDAPServer(t *testing.T, responses map[string]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL + "/rdap/"
		switch r.URL.Path {
		case "/bootstrap/dns.json":
			_, _ = w.Write([]byte(`{"version":"1.0","services":[[["com","net"],["` + base + `"]],[["org"],["https://org.invalid/"]]]}`))
			return
		case "/bootstrap/ipv4.json":
			_, _ = w.Write([]byte(`{"version":"1.0","services":[[["192.0.0.0/8"],["https://wrong.invalid/"]],[["192.0.2.0/24"],["` + base + `"]]]}`))
			return
		case "/bootstrap/ipv6.json":
			_, _ = w.Write([]byte(`{"version":"1.0","services":[[["2001:db8::/32"],["` + base + `"]]]}`))
			return
		}
		if body, ok := responses[strings.TrimPrefix(r.URL.Path, "/rdap/")]; ok {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	}))
	t.Cleanup(srv.Close)

	orig := lookup.RDAPBootstrapBaseURL
	lookup.RDAPBootstrapBaseURL = srv.URL + "/bootstrap/"
	t.Cleanup(func() { lookup.RDAPBootstrapBaseURL = orig })
	return srv
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
