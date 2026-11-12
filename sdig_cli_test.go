package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/miekg/dns"

	"dlookup/lookup"
)

// startTestDNS runs a UDP DNS server on 127.0.0.1 answering every A query
// with 192.0.2.1 (TTL ttl()) and MX queries with "10 mail.<name>".
func startTestDNS(t *testing.T, ttl func() uint32) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		q := req.Question[0]
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: ttl()}
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.1")})
		case dns.TypeMX:
			m.Answer = append(m.Answer, &dns.MX{Hdr: hdr, Preference: 10, Mx: "mail." + q.Name})
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var started sync.WaitGroup
	started.Add(1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: started.Done}
	go func() { _ = srv.ActivateAndServe() }()
	started.Wait()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func fixedTTL(n uint32) func() uint32 { return func() uint32 { return n } }

func TestParseSDIGArgs(t *testing.T) {
	sdigGetenv = func(string) string { return "" }
	t.Cleanup(func() { sdigGetenv = os.Getenv })

	a, err := parseSDIGArgs([]string{"@192.0.2.53", "5300", "example.com", "mx", "tcp", "hidettl", "class", "3", "recurse", "ednssubnet", "198.51.100.0/24", "dnssec", "hidesoadetails", "showflags", "opcode", "0"})
	if err != nil {
		t.Fatal(err)
	}
	r := a.req
	if a.name != "example.com" || a.qtype != "mx" || r.Server != "192.0.2.53:5300" || !r.Recurse || !r.DNSSEC || !r.TCP || r.DoT ||
		r.Class != 3 || r.ECS == nil || r.ECS.String() != "198.51.100.0/24" ||
		!a.format.HideTTL || !a.format.HideSOADetails || !a.format.ShowFlags {
		t.Errorf("parsed %+v / %+v", a, r)
	}

	// Defaults: no RD, no EDNS, UDP; IPv6 server.
	a, err = parseSDIGArgs([]string{"2001:db8::53", "53", "example.com", "A"})
	if err != nil {
		t.Fatal(err)
	}
	if a.req.Recurse || a.req.DNSSEC || a.req.TCP || a.req.ECS != nil || a.req.Server != "[2001:db8::53]:53" {
		t.Errorf("defaults: %+v", a.req)
	}

	// dot implies tcp.
	if a, _ = parseSDIGArgs([]string{"1.1.1.1", "853", "example.com", "A", "dot", "insecure"}); !a.req.DoT || !a.req.TCP || !a.req.Insecure {
		t.Errorf("dot: %+v", a.req)
	}

	errCases := []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"1.1.1.1", "53", "example.com"}, 1, sdigUsage},
		{[]string{"1.1.1.1", "53", "example.com", "A", "bogus"}, 1, "bogus: unknown argument\n"},
		{[]string{"1.1.1.1", "53", "example.com", "A", "recurse", "class"}, 1, "class needs an argument\n"},
		{[]string{"1.1.1.1", "53", "example.com", "A", "ednssubnet"}, 1, "ednssubnet needs an argument\n"},
		{[]string{"1.1.1.1", "53", "example.com", "A", "dumpluaraw"}, 1, "dumpluaraw: not supported by dlookup sdig\n"},
		{[]string{"1.1.1.1", "53", "example.com", "A", "proxy", "0", "1.2.3.4:5", "5.6.7.8:53"}, 1, "proxy: not supported by dlookup sdig\n"},
		{[]string{"ns1.example.com", "53", "example.com", "A"}, 0, "Fatal: Unable to convert presentation address 'ns1.example.com'\n"},
		{[]string{"1.1.1.1", "53", "-", "-"}, 0, "Fatal: multi-query from stdin only supported for tcp\n"},
	}
	for _, c := range errCases {
		_, err := parseSDIGArgs(c.args)
		e, ok := err.(errSDIGExit)
		if !ok || e.code != c.code || e.msg != c.msg {
			t.Errorf("%v: err = %#v, want code %d %q", c.args, err, c.code, c.msg)
		}
	}
}

func TestRunSDIG(t *testing.T) {
	var got lookup.SDIGRequest
	sdigExchange = func(_ context.Context, r lookup.SDIGRequest) (*dns.Msg, error) {
		got = r
		q, _ := r.Msg()
		m := new(dns.Msg)
		m.SetReply(q)
		m.RecursionAvailable = true
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("93.184.216.34")})
		if r.DNSSEC {
			opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			opt.SetUDPSize(1232)
			opt.SetDo()
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: 3, ExtraText: "stale"})
			m.Extra = append(m.Extra, opt)
		}
		return m, nil
	}
	t.Cleanup(func() { sdigExchange = lookup.SDIGExchange })

	var stdout, stderr bytes.Buffer
	code := run([]string{"sdig", "1.1.1.1", "53", "example.com", "a", "recurse"}, strings.NewReader(""), &stdout, &stderr)
	want := "Reply to question for qname='example.com.', qtype=A\n" +
		"Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 0, opcode: 0\n" +
		"0\texample.com.\t300\tIN\tA\t93.184.216.34\n"
	if code != 0 || stdout.String() != want || stderr.String() != "" {
		t.Errorf("code=%d\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if got.Server != "1.1.1.1:53" || !got.Recurse || got.QType != dns.TypeA || got.TCFallback {
		t.Errorf("request %+v", got)
	}

	// EDNS option lines go to stderr; options in any order.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"sdig", "1.1.1.1", "53", "example.com", "A", "hidettl", "dnssec"}, strings.NewReader(""), &stdout, &stderr)
	want = "Reply to question for qname='example.com.', qtype=A\n" +
		"Rcode: 0 (No Error), RD: 0, QR: 1, TC: 0, AA: 0, opcode: 0\n" +
		"0\texample.com.\t[ttl]\tIN\tA\t93.184.216.34\n" +
		"2\t.\t[ttl]\tIN\tOPT\tAA8ABwADc3RhbGU=\n"
	if code != 0 || stdout.String() != want || stderr.String() != "EDNS Extended Error response: 3/stale\n" {
		t.Errorf("code=%d\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if got.Recurse || !got.DNSSEC {
		t.Errorf("request %+v", got)
	}

	for _, c := range []struct {
		args   []string
		code   int
		stderr string
	}{
		{[]string{"sdig", "1.1.1.1", "53", "example.com", "A", "nope"}, 1, "nope: unknown argument\n"},
		{[]string{"sdig", "1.1.1.1", "53", "example.com", "NOPE"}, 0, "Fatal: Unknown DNS type 'NOPE'\n"},
		{[]string{"sdig", "1.1.1.1", "--help"}, 0, sdigUsage},
		{[]string{"sdig"}, 1, sdigUsage},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(c.args, strings.NewReader(""), &stdout, &stderr); code != c.code || stderr.String() != c.stderr || stdout.Len() != 0 {
			t.Errorf("%v: code=%d stderr=%q stdout=%q", c.args, code, stderr.String(), stdout.String())
		}
	}
	stderr.Reset()
	if code := run([]string{"sdig", "--version"}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.HasPrefix(stderr.String(), "sdig ") {
		t.Errorf("--version: %d %q", code, stderr.String())
	}
}

func TestHeadlessSDIG(t *testing.T) {
	addr := startTestDNS(t, fixedTTL(300))
	cfg, err := parseArgs([]string{"-o", "text", "--lookup", "sdig", "--server", addr, "-t", "mx", "--hidettl", "example.com"}, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LookupType() != lookup.SDIGName || cfg.Opts.QType != "MX" || !cfg.Opts.HideTTL || cfg.Opts.NoRecurse {
		t.Fatalf("lookup=%q opts=%+v", cfg.LookupType(), cfg.Opts)
	}
	var out bytes.Buffer
	failed, err := runHeadless(context.Background(), &out, cfg.Provider, cfg.Targets, cfg.Opts, cfg.Output, 1)
	if err != nil || failed != 0 {
		t.Fatalf("failed=%d err=%v", failed, err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "=== example.com [SDIG MX] (") ||
		!strings.Contains(got, "\nReply to question for qname='example.com.', qtype=MX\nRcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 1, opcode: 0\n0\texample.com.\t[ttl]\tIN\tMX\t10 mail.example.com.\n") {
		t.Errorf("output:\n%s", got)
	}

	cfg, err = parseArgs([]string{"--lookup", "sdig", "--norecurse", "--dnssec", "--tcp", "a.com"}, strings.NewReader(""), &bytes.Buffer{})
	if err != nil || !cfg.Opts.NoRecurse || !cfg.Opts.DNSSEC || !cfg.Opts.TCP || cfg.Opts.QType != "" {
		t.Errorf("opts %+v err %v", cfg.Opts, err)
	}
	if cfg, err = parseArgs([]string{"--lookup", "sdig", "--recurse=false", "a.com"}, strings.NewReader(""), &bytes.Buffer{}); err != nil || !cfg.Opts.NoRecurse {
		t.Errorf("--recurse=false: %+v %v", cfg, err)
	}
}

func TestHeadlessDefaultsToOverview(t *testing.T) {
	addr := startTestDNS(t, fixedTTL(300))
	cfg, err := parseArgs([]string{"-o", "text", "--server", addr, "example.com"}, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LookupType() != lookup.OverviewName {
		t.Fatalf("lookup=%q", cfg.LookupType())
	}
	var out bytes.Buffer
	if failed, err := runHeadless(context.Background(), &out, cfg.Provider, cfg.Targets, cfg.Opts, cfg.Output, 1); err != nil || failed != 0 {
		t.Fatalf("failed=%d err=%v", failed, err)
	}
	if got := out.String(); !strings.Contains(got, "Domain example.com is resolving on 192.0.2.1\nTTL:           300\n") {
		t.Errorf("output:\n%s", got)
	}
	// --qtype works with Overview; SDIG-only flags don't.
	if _, err := parseArgs([]string{"-o", "text", "-t", "aaaa", "a.com"}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Errorf("--qtype with overview: %v", err)
	}
	// SDIG-only flags without a lookup pick SDIG; with another lookup they're an error.
	if cfg, err := parseArgs([]string{"-o", "text", "--dnssec", "a.com"}, strings.NewReader(""), &bytes.Buffer{}); err != nil || cfg.LookupType() != lookup.SDIGName {
		t.Errorf("--dnssec without lookup: %v", err)
	}
	if _, err := parseArgs([]string{"-o", "text", "--lookup", "overview", "--dnssec", "a.com"}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Error("--dnssec with overview should be a usage error")
	}
}

func TestTargetsWithoutLookupRunOverview(t *testing.T) {
	addr := startTestDNS(t, fixedTTL(300))
	m := newMainModel([]string{"example.com", "b.example.com"}, "", DefaultConfig(), lookup.Options{Server: addr})
	m, _ = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	if m.dlg != dlgNone || len(m.tabs) != 2 {
		t.Fatalf("dlg=%v tabs=%d", m.dlg, len(m.tabs))
	}
	for _, tab := range m.tabs {
		if tab.lookupType != lookup.OverviewName || tab.state != stateLoading {
			t.Fatalf("tab %q: type=%q state=%v", tab.domain, tab.lookupType, tab.state)
		}
	}
	if m.tabs[0].loadingMsg != "Running Overview on example.com..." {
		t.Errorf("loading msg %q", m.tabs[0].loadingMsg)
	}
	m, _ = settle(t, m, collect(m.Init()))
	for _, tab := range m.tabs {
		if tab.state != stateViewResults || !strings.Contains(tab.result, "Domain "+tab.domain+" is resolving on 192.0.2.1") {
			t.Fatalf("tab %q: state=%v err=%v result=%q", tab.domain, tab.state, tab.err, tab.result)
		}
	}
	if got := m.tabs[0].panelTitle(); !strings.HasPrefix(got, "example.com · Overview · @") {
		t.Errorf("panel title %q", got)
	}
}

func TestLookupDialogSDIGFields(t *testing.T) {
	addr := startTestDNS(t, fixedTTL(300))
	m := homeModel(t, DefaultConfig())
	m.defaultOpts.Server = addr
	m, _ = typeKeys(t, m, "n")
	expectDialog(t, m, dlgLookup)
	if m.dialog.Value("type") != lookup.OverviewName || hasField(m, "qtype") {
		t.Fatalf("default type=%q qtype field=%v", m.dialog.Value("type"), hasField(m, "qtype"))
	}
	// Pick SDIG: its fields appear with their defaults.
	m, _ = typeKeys(t, m, "tab", "space", "SDIG", "enter", "shift+tab")
	if m.dialog.Value("type") != lookup.SDIGName || m.dialog.Value("recurse") != "true" || m.dialog.Value("qtype") != "" || m.dialog.Focused() != "domain" {
		t.Fatalf("SDIG: type=%q recurse=%q qtype=%q focus=%q", m.dialog.Value("type"), m.dialog.Value("recurse"), m.dialog.Value("qtype"), m.dialog.Focused())
	}

	// Choosing another lookup hides the SDIG fields; SDIG brings them back
	// with the values entered before.
	m.dialog.SetValue("dnssec", "true")
	m, _ = typeKeys(t, m, "example.com", "tab", "space", "tui", "enter")
	if m.dialog.Value("type") != tuiFakeName || hasField(m, "qtype") || m.dialog.Value("domain") != "example.com" {
		t.Fatalf("after switching: type=%q qtype field=%v", m.dialog.Value("type"), hasField(m, "qtype"))
	}
	m, _ = typeKeys(t, m, "space", "SDIG", "enter")
	if m.dialog.Value("type") != lookup.SDIGName || !hasField(m, "qtype") || m.dialog.Value("dnssec") != "true" || m.dialog.Focused() != "type" {
		t.Fatalf("after switching back: type=%q dnssec=%q focus=%q", m.dialog.Value("type"), m.dialog.Value("dnssec"), m.dialog.Focused())
	}

	// Select MX in the Query type dropdown and run.
	m, _ = typeKeys(t, m, "tab", "tab", "space", "MX", "enter")
	if m.dialog.Value("qtype") != "MX" {
		t.Fatalf("qtype = %q", m.dialog.Value("qtype"))
	}
	m, msgs := submit(t, m, map[string]string{"dnssec": "false", "hidettl": "true"})
	m, _ = settle(t, m, msgs)
	tab := m.tabs[m.activeTab]
	if tab.lookupType != lookup.SDIGName || tab.lookupOpts.QType != "MX" || !tab.lookupOpts.HideTTL || tab.lookupOpts.DNSSEC || tab.lookupOpts.NoRecurse {
		t.Fatalf("tab type=%q opts=%+v", tab.lookupType, tab.lookupOpts)
	}
	if !strings.Contains(tab.result, "0\texample.com.\t[ttl]\tIN\tMX\t10 mail.example.com.") || !strings.Contains(m.View(), "example.com · SDIG MX") {
		t.Fatalf("result %q\n%s", tab.result, m.View())
	}

	// Change lookup is prefilled from the tab's options.
	m, _ = typeKeys(t, m, "enter")
	expectDialog(t, m, dlgLookup)
	if m.dialog.Value("qtype") != "MX" || m.dialog.Value("hidettl") != "true" || m.dialog.Value("recurse") != "true" || m.dialog.Value("server") != addr {
		t.Errorf("prefill: %v", m.dialog.Values())
	}
	m.dialog.SetValue("recurse", "false")
	m, msgs = send(t, m, keyMsg("enter"))
	m, _ = settle(t, m, msgs)
	if tab := m.tabs[m.activeTab]; !tab.lookupOpts.NoRecurse || !strings.Contains(tab.result, "RD: 0") {
		t.Errorf("recurse off: opts=%+v result=%q", tab.lookupOpts, tab.result)
	}
}

func hasField(m mainModel, key string) bool {
	_, ok := m.dialog.Values()[key]
	return ok
}

func TestWatchIgnoresSDIGTTLChanges(t *testing.T) {
	prev := "Reply to question for qname='example.com.', qtype=A\nRcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 0, opcode: 0\n0\texample.com.\t300\tIN\tA\t192.0.2.1\n2\t.\t0\tIN\tOPT\t"
	cur := strings.Replace(prev, "\t300\t", "\t299\t", 1)
	if added, removed := diffLines(prev, cur); len(added) != 0 || len(removed) != 0 {
		t.Errorf("TTL change reported: added=%v removed=%q", added, removed)
	}
	cur = strings.Replace(prev, "192.0.2.1", "192.0.2.9", 1)
	if added, removed := diffLines(prev, cur); len(added) != 1 || len(removed) != 1 {
		t.Errorf("address change not reported: added=%v removed=%q", added, removed)
	}
}
