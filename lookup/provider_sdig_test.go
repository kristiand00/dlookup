package lookup_test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"dlookup/lookup"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("bad RR %q: %v", s, err)
	}
	return rr
}

// reply builds a response to name/qtype with the given sections.
func reply(t *testing.T, name string, qtype uint16, rd bool, rcode int, answer, ns, extra []string) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.RecursionDesired = rd
	m := new(dns.Msg)
	m.SetRcode(q, rcode)
	m.Authoritative = true
	for _, s := range answer {
		m.Answer = append(m.Answer, mustRR(t, s))
	}
	for _, s := range ns {
		m.Ns = append(m.Ns, mustRR(t, s))
	}
	for _, s := range extra {
		m.Extra = append(m.Extra, mustRR(t, s))
	}
	// Round-trip through the wire format, like a real reply.
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFormatSDIGExact(t *testing.T) {
	soa := "example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300"
	cases := []struct {
		name string
		msg  *dns.Msg
		f    lookup.SDIGFormat
		want string
	}{
		{
			name: "A",
			msg:  reply(t, "example.com.", dns.TypeA, true, dns.RcodeSuccess, []string{"example.com. 300 IN A 192.0.2.1"}, nil, nil),
			want: "Reply to question for qname='example.com.', qtype=A\n" +
				"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"0\texample.com.\t300\tIN\tA\t192.0.2.1\n",
		},
		{
			name: "A hidettl",
			msg:  reply(t, "example.com.", dns.TypeA, false, dns.RcodeSuccess, []string{"example.com. 300 IN A 192.0.2.1", "example.com. 300 IN A 192.0.2.2"}, nil, nil),
			f:    lookup.SDIGFormat{HideTTL: true},
			want: "Reply to question for qname='example.com.', qtype=A\n" +
				"Rcode: 0 (No Error), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"0\texample.com.\t[ttl]\tIN\tA\t192.0.2.1\n" +
				"0\texample.com.\t[ttl]\tIN\tA\t192.0.2.2\n",
		},
		{
			name: "MX",
			msg:  reply(t, "example.com.", dns.TypeMX, true, dns.RcodeSuccess, []string{"example.com. 3600 IN MX 10 mail.example.com.", "example.com. 3600 IN MX 20 ."}, nil, nil),
			want: "Reply to question for qname='example.com.', qtype=MX\n" +
				"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"0\texample.com.\t3600\tIN\tMX\t10 mail.example.com.\n" +
				"0\texample.com.\t3600\tIN\tMX\t20 .\n",
		},
		{
			name: "SOA",
			msg:  reply(t, "example.com.", dns.TypeSOA, true, dns.RcodeSuccess, []string{soa}, nil, nil),
			want: "Reply to question for qname='example.com.', qtype=SOA\n" +
				"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"0\texample.com.\t300\tIN\tSOA\tns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300\n",
		},
		{
			name: "SOA hidesoadetails hidettl",
			msg:  reply(t, "example.com.", dns.TypeSOA, true, dns.RcodeSuccess, []string{soa}, nil, nil),
			f:    lookup.SDIGFormat{HideTTL: true, HideSOADetails: true},
			want: "Reply to question for qname='example.com.', qtype=SOA\n" +
				"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"0\texample.com.\t[ttl]\tIN\tSOA\tns1.example.com. hostmaster.example.com. [serial] 7200 3600 1209600 300\n",
		},
		{
			name: "referral: authority and additional sections",
			msg: reply(t, "www.example.com.", dns.TypeA, false, dns.RcodeSuccess, nil,
				[]string{"example.com. 172800 IN NS ns1.example.net.", "example.com. 172800 IN NS ns2.example.net."},
				[]string{"ns1.example.net. 172800 IN A 192.0.2.53", "ns1.example.net. 172800 IN AAAA 2001:db8::53"}),
			want: "Reply to question for qname='www.example.com.', qtype=A\n" +
				"Rcode: 0 (No Error), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"1\texample.com.\t172800\tIN\tNS\tns1.example.net.\n" +
				"1\texample.com.\t172800\tIN\tNS\tns2.example.net.\n" +
				"2\tns1.example.net.\t172800\tIN\tA\t192.0.2.53\n" +
				"2\tns1.example.net.\t172800\tIN\tAAAA\t2001:db8::53\n",
		},
		{
			name: "NXDOMAIN",
			msg:  reply(t, "nope.example.com.", dns.TypeA, true, dns.RcodeNameError, nil, []string{soa}, nil),
			f:    lookup.SDIGFormat{HideSOADetails: true},
			want: "Reply to question for qname='nope.example.com.', qtype=A\n" +
				"Rcode: 3 (Non-Existent domain), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"1\texample.com.\t300\tIN\tSOA\tns1.example.com. hostmaster.example.com. [serial] 7200 3600 1209600 300\n",
		},
		{
			name: "REFUSED",
			msg:  reply(t, "example.org.", dns.TypeA, false, dns.RcodeRefused, nil, nil, nil),
			want: "Reply to question for qname='example.org.', qtype=A\n" +
				"Rcode: 5 (Query Refused), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0\n",
		},
		{
			name: "TXT CAA DS escaping and hex",
			msg: reply(t, "example.com.", dns.TypeANY, true, dns.RcodeServerFailure, []string{
				`example.com. 60 IN TXT "v=spf1 -all" "say \"hi\"\\ok\009"`,
				`example.com. 60 IN CAA 0 issue "letsencrypt.org"`,
				"example.com. 60 IN DS 12345 13 2 ABCDEF0123",
				"example.com. 60 IN CNAME target.example.net.",
			}, nil, nil),
			want: "Reply to question for qname='example.com.', qtype=ANY\n" +
				"Rcode: 2 (Server Failure), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"0\texample.com.\t60\tIN\tTXT\t\"v=spf1 -all\" \"say \\\"hi\\\"\\\\ok\\009\"\n" +
				"0\texample.com.\t60\tIN\tCAA\t0 issue \"letsencrypt.org\"\n" +
				"0\texample.com.\t60\tIN\tDS\t12345 13 2 abcdef0123\n" +
				"0\texample.com.\t60\tIN\tCNAME\ttarget.example.net.\n",
		},
		{
			name: "DNSSEC: RRSIG, DNSKEY and NSEC3 are abbreviated",
			msg: reply(t, "example.com.", dns.TypeDNSKEY, true, dns.RcodeSuccess, []string{
				"example.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
				"example.com. 3600 IN RRSIG DNSKEY 13 2 3600 20240101000000 20231201000000 12345 example.com. dGVzdA==",
			}, []string{
				"abc.example.com. 300 IN NSEC3 1 1 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG",
			}, nil),
			want: "Reply to question for qname='example.com.', qtype=DNSKEY\n" +
				"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"0\texample.com.\t3600\tIN\tDNSKEY\t257 3 13 ...\n" +
				"0\texample.com.\t3600\tIN\tRRSIG\tDNSKEY 13 2 3600 [expiry] [inception] [keytag] example.com. ...\n" +
				"1\tabc.example.com.\t300\tIN\tNSEC3\t1 [flags] 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG\n",
		},
		{
			name: "NSEC3 showflags",
			msg: reply(t, "example.com.", dns.TypeA, true, dns.RcodeSuccess, nil, []string{
				"abc.example.com. 300 IN NSEC3 1 1 5 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA",
			}, nil),
			f: lookup.SDIGFormat{ShowFlags: true},
			want: "Reply to question for qname='example.com.', qtype=A\n" +
				"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
				"1\tabc.example.com.\t300\tIN\tNSEC3\t1 1 5 aabb 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, edns := lookup.FormatSDIG(tc.msg, tc.f)
			if got != tc.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tc.want)
			}
			if len(edns) != 0 {
				t.Errorf("unexpected EDNS lines %q", edns)
			}
		})
	}
}

func TestFormatSDIGEDNS(t *testing.T) {
	m := reply(t, "example.com.", dns.TypeA, true, dns.RcodeServerFailure, nil, nil, nil)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.SetDo()
	opt.Option = append(opt.Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 16, Address: net.ParseIP("192.0.2.0").To4()},
		&dns.EDNS0_EDE{InfoCode: 22, ExtraText: "at delegation example.com."},
		&dns.EDNS0_PADDING{Padding: make([]byte, 5)},
	)
	m.Extra = append(m.Extra, opt)
	got, edns := lookup.FormatSDIG(m, lookup.SDIGFormat{})
	want := "Reply to question for qname='example.com.', qtype=A\n" +
		"Rcode: 2 (Server Failure), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
		"2\t.\t32768\tIN\tOPT\tAAgABwABGBDAAAIADwAcABZhdCBkZWxlZ2F0aW9uIGV4YW1wbGUuY29tLgAMAAUAAAAAAA==\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
	wantEDNS := []string{
		"EDNS Subnet response: 192.0.2.0/24, scope: 192.0.0.0/16, family = " + strconv.Itoa(syscall.AF_INET),
		"EDNS Extended Error response: 22/at delegation example.com.",
		"EDNS Padding size: 5",
	}
	if !equalSlices(edns, wantEDNS) {
		t.Errorf("edns = %q\nwant  %q", edns, wantEDNS)
	}

	// Empty OPT: the line ends with a tab, as in sdig.
	m = reply(t, "example.com.", dns.TypeA, true, dns.RcodeSuccess, nil, nil, nil)
	m.SetEdns0(1232, false)
	got, _ = lookup.FormatSDIG(m, lookup.SDIGFormat{HideTTL: true})
	if !strings.HasSuffix(got, "\n2\t.\t[ttl]\tIN\tOPT\t\n") {
		t.Errorf("empty OPT line: %q", got)
	}
}

// sdigServer is a UDP+TCP test server that records the queries it gets.
type sdigServer struct {
	addr string
	mu   sync.Mutex
	reqs []*dns.Msg
	nets []string
}

func (s *sdigServer) last(t *testing.T) (*dns.Msg, string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		t.Fatal("no query received")
	}
	return s.reqs[len(s.reqs)-1], s.nets[len(s.nets)-1]
}

// startSDIGServer answers example.com A/MX authoritatively, NXDOMAIN for
// nx.example.com, and a referral otherwise.
func startSDIGServer(t *testing.T) *sdigServer {
	t.Helper()
	s := &sdigServer{}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		s.mu.Lock()
		s.reqs = append(s.reqs, req.Copy())
		s.nets = append(s.nets, w.RemoteAddr().Network())
		s.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		switch {
		case q.Name == "example.com." && q.Qtype == dns.TypeA:
			m.Authoritative = true
			m.Answer = append(m.Answer, mustRR(t, "example.com. 300 IN A 192.0.2.1"))
		case q.Name == "example.com." && q.Qtype == dns.TypeMX:
			m.Authoritative = true
			m.Answer = append(m.Answer, mustRR(t, "example.com. 300 IN MX 10 mail.example.com."))
		case q.Name == "nx.example.com.":
			m.Authoritative = true
			m.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, mustRR(t, "example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1 2 3 4 5"))
		case q.Name == "1.2.0.192.in-addr.arpa." && q.Qtype == dns.TypePTR:
			m.Answer = append(m.Answer, mustRR(t, "1.2.0.192.in-addr.arpa. 300 IN PTR host.example.com."))
		default:
			m.Ns = append(m.Ns, mustRR(t, "com. 172800 IN NS a.gtld-servers.net."))
			m.Extra = append(m.Extra, mustRR(t, "a.gtld-servers.net. 172800 IN A 192.5.6.30"))
		}
		if o := req.IsEdns0(); o != nil {
			m.SetEdns0(1232, o.Do())
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	udp := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: wg.Done}
	tcp := &dns.Server{Listener: ln, Handler: handler, NotifyStartedFunc: wg.Done}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	wg.Wait()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	s.addr = pc.LocalAddr().String()
	return s
}

func sdigProvider(t *testing.T) lookup.LookupProvider {
	t.Helper()
	p, ok := lookup.GetProvider(lookup.SDIGName)
	if !ok {
		t.Fatal("SDIG provider not registered")
	}
	return p
}

func TestSDIGProviderDefaults(t *testing.T) {
	srv := startSDIGServer(t)
	p := sdigProvider(t)
	if p.FlagName() != "sdig" || p.Command() != "" {
		t.Errorf("flag=%q command=%q", p.FlagName(), p.Command())
	}
	if e, ok := p.(lookup.ReportExcluder); !ok || !e.ExcludeFromReport() {
		t.Error("SDIG must be excluded from the Report")
	}
	out, err := p.Execute(context.Background(), "example.com", lookup.Options{Server: srv.addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	want := "Reply to question for qname='example.com.', qtype=A\n" +
		"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
		"0\texample.com.\t300\tIN\tA\t192.0.2.1"
	if out != want {
		t.Errorf("got %q\nwant %q", out, want)
	}
	req, network := srv.last(t)
	if !req.RecursionDesired || req.IsEdns0() != nil || network != "udp" || len(req.Question) != 1 || req.Question[0].Qclass != dns.ClassINET {
		t.Errorf("query: rd=%v edns=%v net=%s q=%v", req.RecursionDesired, req.IsEdns0() != nil, network, req.Question)
	}
}

func TestSDIGProviderOptions(t *testing.T) {
	srv := startSDIGServer(t)
	p := sdigProvider(t)
	ctx := context.Background()

	out, err := p.Execute(ctx, "example.com", lookup.Options{Server: srv.addr, QType: "mx", NoRecurse: true, DNSSEC: true, TCP: true, HideTTL: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "Reply to question for qname='example.com.', qtype=MX\n" +
		"Rcode: 0 (No Error), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0\n" +
		"0\texample.com.\t[ttl]\tIN\tMX\t10 mail.example.com.\n" +
		"2\t.\t[ttl]\tIN\tOPT\t"
	if out != want {
		t.Errorf("got %q\nwant %q", out, want)
	}
	req, network := srv.last(t)
	opt := req.IsEdns0()
	if req.RecursionDesired || opt == nil || !opt.Do() || opt.UDPSize() != lookup.SDIGDefaultBufSize || network != "tcp" {
		t.Errorf("query: rd=%v opt=%v net=%s", req.RecursionDesired, opt, network)
	}

	// NXDOMAIN is output, not an error.
	out, err = p.Execute(ctx, "nx.example.com", lookup.Options{Server: srv.addr})
	if err != nil || !strings.Contains(out, "Rcode: 3 (Non-Existent domain), RD: 1") || !strings.Contains(out, "\n1\texample.com.\t300\tIN\tSOA\t") {
		t.Errorf("NXDOMAIN: %v\n%s", err, out)
	}

	// An IP target is looked up as PTR on its reverse name.
	out, err = p.Execute(ctx, "192.0.2.1", lookup.Options{Server: srv.addr})
	if err != nil || !strings.HasPrefix(out, "Reply to question for qname='1.2.0.192.in-addr.arpa.', qtype=PTR\n") ||
		!strings.HasSuffix(out, "0\t1.2.0.192.in-addr.arpa.\t300\tIN\tPTR\thost.example.com.") {
		t.Errorf("PTR: %v\n%s", err, out)
	}
	if got := lookup.SDIGLabel("192.0.2.1", lookup.Options{}); got != "SDIG PTR" {
		t.Errorf("label = %q", got)
	}
	if got := lookup.SDIGLabel("example.com", lookup.Options{QType: "aaaa"}); got != "SDIG AAAA" {
		t.Errorf("label = %q", got)
	}

	// ECS is sent.
	if _, err := p.Execute(ctx, "example.com", lookup.Options{Server: srv.addr, EDNSSubnet: "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	req, _ = srv.last(t)
	var ecs *dns.EDNS0_SUBNET
	if o := req.IsEdns0(); o != nil {
		for _, op := range o.Option {
			if e, ok := op.(*dns.EDNS0_SUBNET); ok {
				ecs = e
			}
		}
	}
	if ecs == nil || ecs.SourceNetmask != 24 || !ecs.Address.Equal(net.ParseIP("198.51.100.0")) {
		t.Errorf("ECS = %+v", ecs)
	}

	// Class is passed through.
	if _, err := p.Execute(ctx, "example.com", lookup.Options{Server: srv.addr, Class: dns.ClassCHAOS, QType: "TXT"}); err != nil {
		t.Fatal(err)
	}
	if req, _ = srv.last(t); req.Question[0].Qclass != dns.ClassCHAOS || req.Question[0].Qtype != dns.TypeTXT {
		t.Errorf("question = %v", req.Question[0])
	}

	// Bad query type.
	if _, err := p.Execute(ctx, "example.com", lookup.Options{Server: srv.addr, QType: "BOGUS"}); err == nil || !strings.Contains(err.Error(), "Unknown DNS type 'BOGUS'") {
		t.Errorf("err = %v", err)
	}
}

func TestParseQType(t *testing.T) {
	for in, want := range map[string]uint16{"a": dns.TypeA, "MX": dns.TypeMX, "TYPE65": 65, "https": dns.TypeHTTPS, "dnskey": dns.TypeDNSKEY} {
		if got, err := lookup.ParseQType(in); err != nil || got != want {
			t.Errorf("ParseQType(%q) = %d, %v", in, got, err)
		}
	}
	if _, err := lookup.ParseQType("NOPE"); err == nil {
		t.Error("NOPE accepted")
	}
}
