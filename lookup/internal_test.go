package lookup

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestFilterTXT(t *testing.T) {
	rrs := []dns.RR{
		mustRR(t, `a. 60 IN TXT "v=spf1 -all"`),
		mustRR(t, `a. 60 IN TXT "V=SPF1 include:x" " ~all"`),
		mustRR(t, `a. 60 IN TXT "v=spf1"`),
		mustRR(t, `a. 60 IN TXT "v=spf10 nope"`),
		mustRR(t, `a. 60 IN TXT "verification=1"`),
		mustRR(t, `a. 60 IN TXT "v=sp" "f1 split-across-strings"`),
		mustRR(t, `a. 60 IN CNAME b.`),
		mustRR(t, `_dmarc.a. 60 IN TXT "v=DMARC1; p=none"`),
		mustRR(t, `_dmarc.a. 60 IN TXT "v=DMARC1;p=none"`),
	}
	got := filterTXT(rrs, "v=spf1")
	if len(got) != 4 {
		t.Errorf("SPF filter kept %d records, want 4: %v", len(got), got)
	}
	got = filterTXT(rrs, "v=DMARC1")
	if len(got) != 2 {
		t.Errorf("DMARC filter kept %d records, want 2: %v", len(got), got)
	}
}

func TestDMARCName(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":        "_dmarc.example.com",
		"example.com.":       "_dmarc.example.com",
		"_dmarc.example.com": "_dmarc.example.com",
		"sub.example.co.uk":  "_dmarc.sub.example.co.uk",
	} {
		if got := dmarcName(in); got != want {
			t.Errorf("dmarcName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServerAddr(t *testing.T) {
	for in, want := range map[string]string{
		"1.1.1.1":      "1.1.1.1:53",
		"1.1.1.1:5353": "1.1.1.1:5353",
		"2606:4700::":  "[2606:4700::]:53",
		"[::1]":        "[::1]:53",
		"[::1]:5353":   "[::1]:5353",
		"dns.google":   "dns.google:53",
		" 9.9.9.9 ":    "9.9.9.9:53",
	} {
		if got := serverAddr(in); got != want {
			t.Errorf("serverAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadResolvConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	conf := "# comment\nsearch example.com\nnameserver 192.0.2.53\nnameserver 2001:db8::53\noptions ndots:1\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadResolvConf(path)
	want := []string{"192.0.2.53:53", "[2001:db8::53]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("loadResolvConf = %v, want %v", got, want)
	}
	if got := loadResolvConf(filepath.Join(dir, "missing")); got != nil {
		t.Errorf("missing file: got %v, want nil", got)
	}
}

func TestBootstrapLookup(t *testing.T) {
	bs, err := parseBootstrap([]byte(`{"services":[
		[["com","net"],["http://a.example/","https://a.example/"]],
		[["uk"],["https://uk.example/"]],
		[["co.uk"],["https://couk.example/"]],
		[["10.0.0.0/8"],["https://ten.example/"]],
		[["10.1.0.0/16"],["https://tenone.example/"]],
		[["2001:db8::/32"],["https://v6.example/"]]
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"example.com":    "https://a.example/",
		"EXAMPLE.NET.":   "https://a.example/",
		"example.co.uk":  "https://couk.example/",
		"example.org.uk": "https://uk.example/",
	} {
		if got, ok := bs.lookupDomain(name); !ok || got != want {
			t.Errorf("lookupDomain(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	if _, ok := bs.lookupDomain("example.org"); ok {
		t.Error("lookupDomain(example.org) should fail")
	}
	if _, ok := bs.lookupDomain("notcom"); ok {
		t.Error("lookupDomain(notcom) should not match suffix 'com'")
	}
	for ip, want := range map[string]string{
		"10.2.3.4":    "https://ten.example/",
		"10.1.3.4":    "https://tenone.example/",
		"2001:db8::1": "https://v6.example/",
	} {
		if got, ok := bs.lookupIP(net.ParseIP(ip)); !ok || got != want {
			t.Errorf("lookupIP(%q) = %q, %v; want %q", ip, got, ok, want)
		}
	}
	if _, err := parseBootstrap([]byte(`{"services":[]}`)); err == nil {
		t.Error("empty bootstrap should fail")
	}
}

func TestReportExcludesANY(t *testing.T) {
	p, _ := GetProvider("DIG (ANY)")
	if !excludedFromReport(p) {
		t.Error("DIG (ANY) should be excluded from the report")
	}
	p, _ = GetProvider("DIG (A)")
	if excludedFromReport(p) {
		t.Error("DIG (A) should be in the report")
	}
	for _, name := range GetComprehensiveReportOrder() {
		if name == "DIG (ANY)" {
			t.Error("report order should not list DIG (ANY)")
		}
	}
}
