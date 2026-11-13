package lookup_test

import (
	"context"
	"dlookup/lookup"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

var digProviderTestCases = []struct {
	name         string
	expectedFlag string
}{
	{"DIG (ANY)", "dig-any"},
	{"DIG (A)", "dig-a"},
	{"DIG (AAAA)", "dig-aaaa"},
	{"DIG (MX)", "dig-mx"},
	{"DIG (TXT)", "dig-txt"},
	{"DIG (SOA)", "dig-soa"},
	{"DIG (CNAME)", "dig-cname"},
	{"DIG (NS)", "dig-ns"},
	{"DIG (CAA)", "dig-caa"},
	{"DIG (PTR)", "dig-ptr"},
	{"DIG (SPF)", "dig-spf"},
	{"DIG (DMARC)", "dig-dmarc"},
}

func TestDigProviders_StaticMethods(t *testing.T) {
	for _, tc := range digProviderTestCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, ok := lookup.GetProvider(tc.name)
			if !ok {
				t.Fatalf("Expected provider %q not found.", tc.name)
			}
			if name := provider.Name(); name != tc.name {
				t.Errorf("Name() = %q, want %q", name, tc.name)
			}
			if flagName := provider.FlagName(); flagName != tc.expectedFlag {
				t.Errorf("FlagName() = %q, want %q", flagName, tc.expectedFlag)
			}
			if p, ok := lookup.GetProviderByFlagName(tc.expectedFlag); !ok || p.Name() != tc.name {
				t.Errorf("GetProviderByFlagName(%q) did not return %q", tc.expectedFlag, tc.name)
			}
			legacy := "dig-" + tc.expectedFlag // old "dig-dig-a" style still resolves
			if p, ok := lookup.GetProviderByFlagName(legacy); !ok || p.Name() != tc.name {
				t.Errorf("GetProviderByFlagName(%q) did not return %q", legacy, tc.name)
			}
			usage := provider.Usage()
			if !strings.HasPrefix(usage, "Run "+tc.name) || !strings.HasSuffix(usage, "lookup on domains from <filename>") {
				t.Errorf("Usage() = %q", usage)
			}
			if provider.Command() != "" || !provider.CheckAvailability() {
				t.Errorf("native provider should have Command()==\"\" and be available")
			}
		})
	}
}

func runDig(t *testing.T, server, provider, target string) (string, error) {
	t.Helper()
	p, ok := lookup.GetProvider(provider)
	if !ok {
		t.Fatalf("provider %q not found", provider)
	}
	return p.Execute(context.Background(), target, lookup.Options{Server: server, Timeout: 5 * time.Second})
}

func TestDigProviders_Execute(t *testing.T) {
	server := startDNSServer(t)

	cases := []struct {
		provider, target string
		want             []string // substrings that must appear
		notWant          []string
	}{
		{"DIG (A)", "example.com", []string{"example.com. 300 IN A 192.0.2.1"}, nil},
		{"DIG (A)", "EXAMPLE.com.", []string{"192.0.2.1"}, nil},
		{"DIG (A)", "www.example.com", []string{"www.example.com. 300 IN CNAME example.com."}, nil},
		{"DIG (AAAA)", "example.com", []string{"IN AAAA 2001:db8::1"}, nil},
		{"DIG (MX)", "example.com", []string{"IN MX 10 mail.example.com."}, nil},
		{"DIG (NS)", "example.com", []string{"IN NS ns1.example.com.", "IN NS ns2.example.com."}, nil},
		{"DIG (SOA)", "example.com", []string{"IN SOA ns1.example.com. hostmaster.example.com. 2024010101"}, nil},
		{"DIG (CAA)", "example.com", []string{`IN CAA 0 issue "letsencrypt.org"`}, nil},
		{"DIG (TXT)", "example.com", []string{"v=spf1", "google-site-verification"}, nil},
		{"DIG (SPF)", "example.com", []string{`"v=spf1 include:_spf.example.net -all"`}, []string{"google-site-verification", "spf10"}},
		{"DIG (DMARC)", "example.com", []string{`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`}, []string{"unrelated"}},
		{"DIG (PTR)", "192.0.2.1", []string{"1.2.0.192.in-addr.arpa. 300 IN PTR host.example.com."}, nil},
		{"DIG (PTR)", "2001:db8::1", []string{"ip6.arpa. 300 IN PTR host6.example.com."}, nil},
		{"DIG (PTR)", "1.2.0.192.in-addr.arpa", []string{"PTR host.example.com."}, nil},
		{"DIG (PTR)", "example.com", []string{"; 192.0.2.1", "PTR host.example.com.", "; 2001:db8::1", "PTR host6.example.com."}, nil},
		{"DIG (CNAME)", "example.com", []string{"(No results found)"}, nil},
		{"DIG (SPF)", "www.example.com", []string{"(No results found)"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.provider+"/"+tc.target, func(t *testing.T) {
			out, err := runDig(t, server, tc.provider, tc.target)
			if err != nil {
				t.Fatalf("Execute error: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("output unexpectedly contains %q:\n%s", w, out)
				}
			}
			if strings.Contains(out, "\t") {
				t.Errorf("output should not contain tabs:\n%q", out)
			}
		})
	}
}

func TestDigProviders_Errors(t *testing.T) {
	server := startDNSServer(t)

	_, err := runDig(t, server, "DIG (A)", "nope.test")
	var dnsErr *lookup.DNSError
	if !errors.As(err, &dnsErr) || dnsErr.Rcode != "NXDOMAIN" {
		t.Errorf("NXDOMAIN: err = %v, want *DNSError with NXDOMAIN", err)
	}

	_, err = runDig(t, server, "DIG (ANY)", "example.com")
	if !errors.As(err, &dnsErr) || dnsErr.Rcode != "NOTIMP" {
		t.Errorf("ANY: err = %v, want *DNSError with NOTIMP", err)
	}

	for _, bad := range []string{"-x", "+short", "a b.com", ""} {
		if _, err := runDig(t, server, "DIG (A)", bad); err == nil {
			t.Errorf("target %q: expected validation error", bad)
		}
	}
	if _, err := runDig(t, "-oops", "DIG (A)", "example.com"); err == nil {
		t.Error("invalid server: expected error")
	}
	if _, err := runDig(t, server, "DIG (DMARC)", "192.0.2.1"); err == nil {
		t.Error("DMARC on IP: expected error")
	}
}

// TestDigProvider_Server checks server address forms (default port, explicit
// port) using only local addresses.
func TestDigProvider_Server(t *testing.T) {
	server := startDNSServer(t)
	host, port, _ := net.SplitHostPort(server)

	if out, err := runDig(t, net.JoinHostPort(host, port), "DIG (A)", "example.com"); err != nil || !strings.Contains(out, "192.0.2.1") {
		t.Errorf("host:port: out=%q err=%v", out, err)
	}

	// Bare host means port 53. Nothing listens on 127.0.0.1:53 in tests (or if
	// something does, it won't know example.com's test data), so we only check
	// the error message names port 53. Bound by a short timeout.
	p, _ := lookup.GetProvider("DIG (A)")
	_, err := p.Execute(context.Background(), "example.com", lookup.Options{Server: "127.0.0.1", Timeout: 300 * time.Millisecond})
	if err != nil && !strings.Contains(err.Error(), "127.0.0.1:53") && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("bare host: unexpected error %v", err)
	}
}

func TestDigProvider_ContextCancel(t *testing.T) {
	// A UDP socket that never answers.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	p, _ := lookup.GetProvider("DIG (A)")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = p.Execute(ctx, "example.com", lookup.Options{Server: pc.LocalAddr().String(), Timeout: 10 * time.Second})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Execute took %v, ctx not honoured", d)
	}
}

func TestReverseName(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":   "1.2.0.192.in-addr.arpa",
		"8.8.4.4":     "4.4.8.8.in-addr.arpa",
		"2001:db8::1": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
	}
	for ip, want := range cases {
		got, err := lookup.ReverseName(ip)
		if err != nil || got != want {
			t.Errorf("ReverseName(%q) = %q, %v; want %q", ip, got, err, want)
		}
	}
	if _, err := lookup.ReverseName("example.com"); err == nil {
		t.Error("ReverseName(example.com): expected error")
	}
}

func ExampleReverseName() {
	name, _ := lookup.ReverseName("192.0.2.1")
	fmt.Println(name)
	// Output: 1.2.0.192.in-addr.arpa
}
