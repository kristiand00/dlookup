package lookup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSPFParse(t *testing.T) {
	cases := []struct {
		rec     string
		wantErr string // substring of the first error; "" = valid
		terms   int
	}{
		{"v=spf1 -all", "", 1},
		{"V=SPF1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx/24 a:mail.example.com/28//64 ~all", "", 6},
		{"v=spf1 include:_spf.example.net redirect=_spf.example.org exp=explain.example.com", "", 3},
		{"v=spf1 exists:%{i}._spf.example.com -all", "", 2},
		{"v=spf1 ptr ?all", "", 2},
		{"v=spf1 ptr:example.com -all", "", 2},
		{"spf1 -all", "does not start with v=spf1", 0},
		{"v=spf1 ip4:300.1.1.1 -all", "invalid ip4 network", 2},
		{"v=spf1 ip4:192.0.2.0/33 -all", "invalid ip4 network", 2},
		{"v=spf1 ip6:192.0.2.1 -all", "invalid ip6 network", 2},
		{"v=spf1 include -all", "include needs a domain", 2},
		{"v=spf1 foo:bar -all", "unknown mechanism", 2},
		{"v=spf1 all:x", "takes no argument", 1},
		{"v=spf1 a/40 -all", "out of range", 2},
		{"v=spf1 redirect=a.example redirect=b.example", "more than once", 2},
		{"v=spf1 include:bad..domain -all", "invalid domain", 2},
	}
	for _, c := range cases {
		terms, errs := spfParse(c.rec)
		if c.wantErr == "" && len(errs) > 0 {
			t.Errorf("%q: unexpected errors %v", c.rec, errs)
		}
		if c.wantErr != "" && (len(errs) == 0 || !strings.Contains(errs[0], c.wantErr)) {
			t.Errorf("%q: errors %v, want %q", c.rec, errs, c.wantErr)
		}
		if len(terms) != c.terms {
			t.Errorf("%q: %d terms, want %d", c.rec, len(terms), c.terms)
		}
	}
	terms, _ := spfParse("v=spf1 -include:x.example ~a ?mx +all")
	quals := ""
	for _, tm := range terms {
		quals += string(tm.qualifier)
	}
	if quals != "-~?+" {
		t.Errorf("qualifiers = %q", quals)
	}
}

func spfRun(t *testing.T, recs ...string) string {
	t.Helper()
	resolver := newFake(t, nil, recs...)
	var r chkReport
	emailCheckSPF(context.Background(), testOpts(resolver), "example.test.", &r)
	return r.String()
}

func TestSPFLookupCounting(t *testing.T) {
	out := spfRun(t,
		`example.test. 300 IN TXT "v=spf1 include:a.example.test mx a:host.example.test -all"`,
		`example.test. 300 IN MX 10 mx.example.test.`,
		`host.example.test. 300 IN A 192.0.2.1`,
		`a.example.test. 300 IN TXT "v=spf1 include:b.example.test include:c.example.test ~all"`,
		`b.example.test. 300 IN TXT "v=spf1 ip4:192.0.2.0/24 exists:%{i}.x.example.test ~all"`,
		`c.example.test. 300 IN TXT "v=spf1 redirect=d.example.test"`,
		`d.example.test. 300 IN TXT "v=spf1 a -all"`,
		`d.example.test. 300 IN A 192.0.2.4`,
	)
	// include:a(1) mx(1) a(1) + a: include b(1) exists(1) include c(1) redirect d(1) a(1) = 8
	mustContain(t, out,
		"✓ 8/10 DNS lookups (macros not expanded)",
		"include:a.example.test (6 lookups)",
		"  include:b.example.test (2 lookups)",
		"    redirect=d.example.test (2 lookups)",
		"✓ 0/2 void lookups",
		"✓ ends with -all (fail)",
		"0 warnings, 0 problems",
	)
}

func TestSPFTooManyLookupsAndVoids(t *testing.T) {
	recs := []string{`example.test. 300 IN TXT "v=spf1 include:i1.example.test include:i2.example.test a:void1.example.test a:void2.example.test mx:void3.example.test ?all"`}
	for i := 1; i <= 2; i++ {
		var inc []string
		for j := 0; j < 5; j++ {
			inc = append(inc, fmt.Sprintf("a:h%d.example.test", j))
			recs = append(recs, fmt.Sprintf("h%d.example.test. 300 IN A 192.0.2.%d", j, j+1))
		}
		recs = append(recs, fmt.Sprintf(`i%d.example.test. 300 IN TXT "v=spf1 %s -all"`, i, strings.Join(inc, " ")))
	}
	out := spfRun(t, recs...)
	mustContain(t, out,
		"✗ 15 DNS lookups, over the limit of 10 (permerror)",
		"✗ 3 void lookups, over the limit of 2 (permerror)",
		"void lookup: a:void1.example.test in example.test finds no records",
		"! ends with ?all (neutral)",
	)
}

func TestSPFLoopMissingIncludeAndMulti(t *testing.T) {
	out := spfRun(t,
		`example.test. 300 IN TXT "v=spf1 include:loop.example.test include:gone.example.test ptr +all"`,
		`loop.example.test. 300 IN TXT "v=spf1 include:example.test -all"`,
	)
	mustContain(t, out,
		"✗ include loop: loop.example.test includes example.test again",
		"✗ include:gone.example.test: domain does not exist (NXDOMAIN)",
		"! uses the ptr mechanism (deprecated",
		"! ends with +all",
		"! 1/2 void lookups",
	)

	out = spfRun(t, `example.test. 300 IN TXT "v=spf1 -all"`, `example.test. 300 IN TXT "v=spf1 ~all"`)
	mustContain(t, out, "✗ 2 SPF records; there must be exactly one")

	out = spfRun(t, `example.test. 300 IN TXT "google-site-verification=x"`)
	mustContain(t, out, "! no SPF record")

	out = spfRun(t, `example.test. 300 IN TXT "v=spf1 a:%{d}.x -all junk:y"`)
	mustContain(t, out, `✗ syntax: "junk:y": unknown mechanism`, "macros not expanded")

	out = spfRun(t, `example.test. 300 IN TXT "v=spf1 -all ip4:192.0.2.1"`)
	mustContain(t, out, "! terms after 'all' are ignored: ip4:192.0.2.1")
}

func TestDMARCParse(t *testing.T) {
	rec := dmarcParse("v=DMARC1; p=Reject; sp=none; pct=50; rua=mailto:a@example.test,mailto:b@rep.example.net!10m; adkim=s")
	if len(rec.errs) != 0 {
		t.Errorf("errs = %v", rec.errs)
	}
	if rec.tags["p"] != "reject" || rec.tags["sp"] != "none" || rec.tags["pct"] != "50" {
		t.Errorf("tags = %v", rec.tags)
	}
	if got := strings.Join(dmarcReportDomains(rec.tags["rua"]), ","); got != "example.test,rep.example.net" {
		t.Errorf("report domains = %q", got)
	}
	for in, want := range map[string]string{
		"p=none; v=DMARC1":                    "must start with v=DMARC1",
		"v=DMARC1; p=block":                   "invalid p=block",
		"v=DMARC1; p=none; pct=150":           "invalid pct=150",
		"v=DMARC1; p=none; adkim=x":           "invalid adkim=x",
		"v=DMARC1; p=none; rua=https://x":     "not a mailto: address",
		"v=DMARC1; p=none; p=reject":          "more than once",
		"v=DMARC1; p=none; garbage":           "invalid tag",
		"v=DMARC1; p=quarantine; sp=sideways": "invalid sp=sideways",
	} {
		rec := dmarcParse(in)
		if len(rec.errs) == 0 || !strings.Contains(strings.Join(rec.errs, "|"), want) {
			t.Errorf("%q: errs %v, want %q", in, rec.errs, want)
		}
	}
}

func dmarcRun(t *testing.T, recs ...string) string {
	t.Helper()
	resolver := newFake(t, nil, recs...)
	var r chkReport
	emailCheckDMARC(context.Background(), testOpts(resolver), "example.test", &r)
	return r.String()
}

func TestDMARCCheck(t *testing.T) {
	out := dmarcRun(t, `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=none; pct=50; rua=mailto:d@reports.example.net"`)
	mustContain(t, out,
		"! p=none: monitoring only",
		"! pct=50",
		"✓ aggregate reports (rua) to mailto:d@reports.example.net",
		"! external report receiver reports.example.net has not authorised this domain (example.test._report._dmarc.reports.example.net)",
	)
	out = dmarcRun(t,
		`_dmarc.example.test. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:d@reports.example.net"`,
		`example.test._report._dmarc.reports.example.net. 300 IN TXT "v=DMARC1"`,
	)
	mustContain(t, out, "✓ p=reject", "0 warnings, 0 problems")
	out = dmarcRun(t, `_dmarc.example.test. 300 IN TXT "v=DMARC1; rua=mailto:x@example.test"`)
	mustContain(t, out, "✗ missing p= policy")
	out = dmarcRun(t, `example.test. 300 IN A 192.0.2.1`)
	mustContain(t, out, "! no DMARC record")
	out = dmarcRun(t, `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=reject"`)
	mustContain(t, out, "! no rua=")
}

func dkimRecord(t *testing.T, bits int) string {
	t.Helper()
	// Only the modulus size matters; Go refuses to generate keys < 1024 bits.
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// txtRR builds a TXT record, splitting long values into 255-byte strings.
func txtRR(name, value string) string {
	var parts []string
	for len(value) > 255 {
		parts = append(parts, `"`+value[:255]+`"`)
		value = value[255:]
	}
	parts = append(parts, `"`+value+`"`)
	return name + " 300 IN TXT " + strings.Join(parts, " ")
}

func TestDKIMParse(t *testing.T) {
	if k := dkimParse(dkimRecord(t, 1024)); k.bits != 1024 || k.keyType != "rsa" || k.err != "" {
		t.Errorf("rsa1024: %+v", k)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if k := dkimParse("v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)); k.keyType != "ed25519" || k.err != "" {
		t.Errorf("ed25519: %+v", k)
	}
	if k := dkimParse("v=DKIM1; p="); !k.revoked {
		t.Errorf("revoked: %+v", k)
	}
	if k := dkimParse("v=DKIM1; p=!!!"); k.err == "" {
		t.Errorf("bad base64 accepted: %+v", k)
	}
	if k := dkimParse("v=DKIM1; k=rsa"); k.err != "no p= tag" {
		t.Errorf("missing p: %+v", k)
	}
}

func TestDKIMProbe(t *testing.T) {
	resolver := newFake(t, nil,
		txtRR("google._domainkey.example.test.", dkimRecord(t, 2048)),
		txtRR("k1._domainkey.example.test.", dkimRecord(t, 1024)),
		txtRR("s1._domainkey.example.test.", dkimRecord(t, 512)),
		"selector1._domainkey.example.test. 300 IN CNAME sel1.dkim.example.net.",
		txtRR("sel1.dkim.example.net.", dkimRecord(t, 2048)),
		`fm1._domainkey.example.test. 300 IN TXT "v=DKIM1; p="`,
	)
	var r chkReport
	emailCheckDKIM(context.Background(), testOpts(resolver), "example.test", &r)
	out := r.String()
	mustContain(t, out,
		"✓ google: RSA 2048 bits",
		"! k1: RSA 1024 bits (2048 recommended)",
		"✗ s1: RSA 512 bits (too weak",
		"✓ selector1: RSA 2048 bits (via sel1.dkim.example.net.)",
		"- fm1: key revoked",
	)
	mustNotContain(t, out, "wildcard")

	resolver = newFake(t, nil, txtRR("*._domainkey.example.test.", dkimRecord(t, 1024)))
	// The fake has no wildcard synthesis; emulate by adding the probe name.
	resolver.add(t, txtRR("dlookup-wildcard-probe-7f3a._domainkey.example.test.", dkimRecord(t, 1024)))
	r = chkReport{}
	emailCheckDKIM(context.Background(), testOpts(resolver), "example.test", &r)
	mustContain(t, r.String(), "answers for any selector (wildcard)", "! no DKIM key found")
}

func TestMTASTSParse(t *testing.T) {
	p := mtaSTSParse("version: STSv1\r\nmode: enforce\r\nmx: mx1.example.test\r\nmx: *.mail.example.net\r\nmax_age: 604800\r\n")
	if len(p.errs) != 0 || p.mode != "enforce" || p.maxAge != 604800 || len(p.mx) != 2 {
		t.Fatalf("policy = %+v", p)
	}
	for host, want := range map[string]bool{
		"mx1.example.test.": true, "a.mail.example.net": true, "a.b.mail.example.net": false,
		"mail.example.net": false, "mx2.example.test": false,
	} {
		if p.matches(host) != want {
			t.Errorf("matches(%q) = %v", host, !want)
		}
	}
	p = mtaSTSParse("version: STSv2\nmode: sometimes\n")
	if len(p.errs) != 4 {
		t.Errorf("errs = %v", p.errs)
	}
}

func TestEmailExecuteWithMTASTS(t *testing.T) {
	policy := "version: STSv1\nmode: testing\nmx: mx1.example.test\nmax_age: 3600\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, policy)
	}))
	t.Cleanup(srv.Close)
	oldURL, oldClient := mtaSTSPolicyURL, mtaSTSHTTPClient
	mtaSTSPolicyURL = func(domain string) string { return srv.URL + "/.well-known/mta-sts.txt" }
	mtaSTSHTTPClient = srv.Client()
	t.Cleanup(func() { mtaSTSPolicyURL, mtaSTSHTTPClient = oldURL, oldClient })

	resolver := newFake(t, nil,
		"example.test. 300 IN MX 10 mx1.example.test.",
		"example.test. 300 IN MX 20 mx2.example.test.",
		"mx1.example.test. 300 IN A 192.0.2.25",
		"mx2.example.test. 300 IN CNAME mx1.example.test.",
		`example.test. 300 IN TXT "v=spf1 mx -all"`,
		`_dmarc.example.test. 300 IN TXT "v=DMARC1; p=none; rua=mailto:d@example.test"`,
		`_mta-sts.example.test. 300 IN TXT "v=STSv1; id=20240101"`,
		`_smtp._tls.example.test. 300 IN TXT "v=TLSRPTv1; rua=mailto:tls@example.test"`,
		`default._bimi.example.test. 300 IN TXT "v=BIMI1; l=https://example.test/logo.svg"`,
	)
	out, err := (&EmailProvider{}).Execute(context.Background(), "example.test", testOpts(resolver))
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out,
		"Email checks for example.test",
		"   10 mx1.example.test.",
		"✓ 2 MX records, all resolve",
		"! MX mx2.example.test. is a CNAME to mx1.example.test.",
		"✓ 1/10 DNS lookups",
		"! policy mode testing",
		"! max_age 3600 is short",
		"✗ MX hosts not covered by the policy's mx: lines (mail to them fails when enforced): mx2.example.test.",
		"✓ v=TLSRPTv1; rua=mailto:tls@example.test",
		"✓ v=BIMI1; l=https://example.test/logo.svg",
		"! BIMI requires a DMARC policy of quarantine or reject",
		"! no DKIM key found",
	)

	// Policy fetch failure.
	policy = ""
	mtaSTSPolicyURL = func(domain string) string { return srv.URL + "/missing" }
	out, _ = (&EmailProvider{}).Execute(context.Background(), "example.test", testOpts(resolver))
	mustContain(t, out, "✗ policy "+srv.URL+"/missing not retrievable: HTTP 404")
}

func TestEmailMXVariants(t *testing.T) {
	run := func(recs ...string) string {
		resolver := newFake(t, nil, recs...)
		var r chkReport
		emailCheckMX(context.Background(), testOpts(resolver), "example.test.", &r)
		return r.String()
	}
	mustContain(t, run("example.test. 300 IN MX 0 ."), "✓ null MX (0 .)")
	mustContain(t, run("example.test. 300 IN MX 0 .", "example.test. 300 IN MX 10 mx.example.test."), "✗ null MX (.) mixed")
	mustContain(t, run("example.test. 300 IN A 192.0.2.1"), "! no MX records: mail falls back to the A record")
	mustContain(t, run("example.test. 300 IN MX 10 gone.example.net."), "✗ no MX host resolves: gone.example.net.")
	mustContain(t, run("other.test. 300 IN A 192.0.2.1"), "✗ example.test. does not exist (NXDOMAIN)")
}
