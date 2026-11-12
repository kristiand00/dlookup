package zonefile

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func parseFile(t *testing.T, path string, f Format, origin string) *Zone {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	z, err := Parse(fh, f, origin)
	if err != nil {
		t.Fatalf("Parse(%s, %s): %v", path, f, err)
	}
	return z
}

func write(t *testing.T, z *Zone, f Format, opts WriteOptions) (string, []string) {
	t.Helper()
	var b bytes.Buffer
	warns, err := WriteWithWarnings(&b, z, f, opts)
	if err != nil {
		t.Fatalf("Write(%s): %v", f, err)
	}
	return b.String(), warns
}

func reparse(t *testing.T, s string, f Format, origin string) *Zone {
	t.Helper()
	z, err := Parse(strings.NewReader(s), f, origin)
	if err != nil {
		t.Fatalf("re-Parse(%s): %v\n%s", f, err, s)
	}
	return z
}

func find(t *testing.T, z *Zone, name, typ string) []Record {
	t.Helper()
	recs := z.Lookup(name, typ)
	if len(recs) == 0 {
		t.Fatalf("no %s %s in zone %s: %+v", name, typ, z.Origin, z.Records)
	}
	return recs
}

func datas(recs []Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.Data
	}
	return out
}

func sameRecords(t *testing.T, label string, got, want []Record) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: records differ\n got: %s\nwant: %s", label, dumpRecs(got), dumpRecs(want))
	}
}

func dumpRecs(recs []Record) string {
	b, _ := json.MarshalIndent(recs, "", " ")
	return string(b)
}

func boolp(b bool) *bool { return &b }

func TestParseBIND(t *testing.T) {
	z := parseFile(t, "testdata/example.zone", BIND, "")
	if z.Origin != "example.com." {
		t.Fatalf("origin = %q", z.Origin)
	}
	soa := find(t, z, "@", "SOA")
	if soa[0].Data != "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300" || soa[0].TTL != 3600 {
		t.Errorf("SOA = %+v", soa[0])
	}
	if z.Records[0].Type != "SOA" {
		t.Errorf("first record = %+v, want the SOA", z.Records[0])
	}
	if got := datas(find(t, z, "example.com.", "NS")); !reflect.DeepEqual(got, []string{"ns1.example.com.", "ns2.example.net."}) {
		t.Errorf("NS = %v", got)
	}
	if got := datas(find(t, z, "", "MX")); !reflect.DeepEqual(got, []string{"10 mail.example.com.", "20 mail2.example.net."}) {
		t.Errorf("MX = %v", got)
	}
	www := find(t, z, "www", "CNAME")[0]
	if www.Data != "example.com." || www.TTL != 300 {
		t.Errorf("www = %+v", www)
	}
	if mail := find(t, z, "mail.example.com.", "A")[0]; mail.Comment != "mail server" {
		t.Errorf("mail comment = %q", mail.Comment)
	}
	find(t, z, "*.dev", "A")
	if srv := find(t, z, "_sip._tcp", "SRV")[0]; srv.Data != "10 60 5060 sip.example.com." {
		t.Errorf("SRV = %q", srv.Data)
	}
	dkim := find(t, z, "selector1._domainkey", "TXT")[0]
	if want := []string{"v=DKIM1; k=rsa; ", "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"}; !reflect.DeepEqual(TXTStrings(dkim.Data), want) {
		t.Errorf("DKIM strings = %q", TXTStrings(dkim.Data))
	}
	if len(z.Records) != 15 {
		t.Errorf("got %d records, want 15", len(z.Records))
	}
}

func TestParseBINDOrigin(t *testing.T) {
	abs := "example.org. 300 IN SOA ns.example.org. h.example.org. 1 2 3 4 5\nwww.example.org. 300 IN A 192.0.2.1\n"
	z, err := Parse(strings.NewReader(abs), BIND, "")
	if err != nil || z.Origin != "example.org." {
		t.Fatalf("origin from SOA: %v %v", z, err)
	}
	rel := "@ 300 IN A 192.0.2.1\nwww 300 IN CNAME @\n"
	if _, err := Parse(strings.NewReader(rel), BIND, ""); err == nil {
		t.Error("relative names without origin: want error")
	}
	z, err = Parse(strings.NewReader(rel), BIND, "Example.NET")
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, z, "www.example.net.", "CNAME")[0].Data; got != "example.net." {
		t.Errorf("www = %q", got)
	}
	if _, err := Parse(strings.NewReader("$INCLUDE /etc/passwd\n"), BIND, "example.com"); err == nil {
		t.Error("$INCLUDE: want error")
	}
	if _, err := Parse(strings.NewReader("www IN A not-an-ip\n"), BIND, "example.com"); err == nil {
		t.Error("bad A: want error")
	}
}

func TestBINDRoundTrip(t *testing.T) {
	z := parseFile(t, "testdata/example.zone", BIND, "")
	out, warns := write(t, z, BIND, WriteOptions{})
	if len(warns) > 0 {
		t.Errorf("warnings: %v", warns)
	}
	for _, want := range []string{"$ORIGIN example.com.\n", "$TTL 3600\n", "\nwww ", " IN SOA ", "2024010101 ; serial", "; mail server"} {
		if !strings.Contains(out, want) {
			t.Errorf("BIND output lacks %q:\n%s", want, out)
		}
	}
	sameRecords(t, "bind round trip", reparse(t, out, BIND, "").Records, z.Records)
}

func TestParseCloudflare(t *testing.T) {
	z := parseFile(t, "testdata/cloudflare.json", Cloudflare, "")
	if z.Origin != "example.com." {
		t.Fatalf("origin = %q", z.Origin)
	}
	a := find(t, z, "@", "A")[0]
	if a.Proxied == nil || !*a.Proxied || a.TTL != 0 || a.Comment != "web origin" {
		t.Errorf("apex A = %+v", a)
	}
	if mail := find(t, z, "mail", "A")[0]; mail.Proxied == nil || *mail.Proxied || mail.TTL != 3600 {
		t.Errorf("mail = %+v", mail)
	}
	if mx := find(t, z, "@", "MX")[0]; mx.Data != "10 mail.example.com." || mx.Proxied != nil {
		t.Errorf("MX = %+v", mx)
	}
	if srv := find(t, z, "_sip._tcp", "SRV")[0]; srv.Data != "10 60 5060 sip.example.com." {
		t.Errorf("SRV = %q", srv.Data)
	}
	if caa := find(t, z, "@", "CAA")[0]; caa.Data != `0 issue "letsencrypt.org"` {
		t.Errorf("CAA = %q", caa.Data)
	}
	if txt := find(t, z, "_dmarc", "TXT")[0]; txt.Data != `"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"` || txt.TTL != 300 {
		t.Errorf("DMARC = %+v", txt)
	}
	if www := find(t, z, "www", "CNAME")[0]; www.Data != "example.com." {
		t.Errorf("www = %q", www.Data)
	}

	// Bare array, legacy SRV data and data-only CAA.
	bare := `[{"name":"_xmpp._tcp.example.org","type":"SRV","ttl":1,"data":{"service":"_xmpp","proto":"_tcp","name":"example.org","priority":5,"weight":0,"port":5222,"target":"xmpp.example.org"}},
	{"name":"example.org","type":"CAA","ttl":300,"data":{"flags":128,"tag":"issuewild","value":";"}},
	{"name":"example.org","type":"TXT","ttl":300,"content":"\"a\" \"b\""}]`
	z, err := Parse(strings.NewReader(bare), Cloudflare, "")
	if err != nil {
		t.Fatal(err)
	}
	if z.Origin != "example.org." {
		t.Errorf("origin = %q", z.Origin)
	}
	if got := find(t, z, "_xmpp._tcp", "SRV")[0].Data; got != "5 0 5222 xmpp.example.org." {
		t.Errorf("SRV = %q", got)
	}
	if got := find(t, z, "@", "CAA")[0].Data; got != `128 issuewild ";"` {
		t.Errorf("CAA = %q", got)
	}
	if got := find(t, z, "@", "TXT")[0].Data; got != `"a" "b"` {
		t.Errorf("TXT = %q", got)
	}
	if _, err := Parse(strings.NewReader(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`), Cloudflare, ""); err == nil {
		t.Error("failed API response: want error")
	}
}

func TestCloudflareRoundTrip(t *testing.T) {
	z := parseFile(t, "testdata/cloudflare.json", Cloudflare, "")
	out, warns := write(t, z, Cloudflare, WriteOptions{})
	if len(warns) > 0 {
		t.Errorf("warnings: %v", warns)
	}
	var recs []map[string]any
	if err := json.Unmarshal([]byte(out), &recs); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, r := range recs {
		if r["name"] == "example.com" && r["type"] == "MX" && (r["content"] != "mail.example.com" || r["priority"] != float64(10)) {
			t.Errorf("MX = %v", r)
		}
		if r["type"] == "SRV" && r["data"] == nil {
			t.Errorf("SRV without data: %v", r)
		}
		if r["type"] == "A" && r["name"] == "example.com" && (r["ttl"] != float64(1) || r["proxied"] != true) {
			t.Errorf("apex A = %v", r)
		}
	}
	sameRecords(t, "cloudflare round trip", reparse(t, out, Cloudflare, "example.com").Records, z.Records)
}

func TestParseRoute53(t *testing.T) {
	z := parseFile(t, "testdata/route53.json", Route53, "")
	if z.Origin != "example.com." {
		t.Fatalf("origin = %q", z.Origin)
	}
	alias := find(t, z, "@", AliasType)[0]
	if alias.Data != "d111111abcdef8.cloudfront.net." || !strings.Contains(alias.Comment, "alias-zone=Z2FDTNDATAQYW2") || !strings.Contains(alias.Comment, "alias-type=A") {
		t.Errorf("alias = %+v", alias)
	}
	if w := find(t, z, "*.example.com.", "A")[0]; w.Data != "192.0.2.50" || w.TTL != 60 {
		t.Errorf("wildcard = %+v", w)
	}
	dkim := find(t, z, "google._domainkey", "TXT")[0]
	strs := TXTStrings(dkim.Data)
	if len(strs) != 2 || len(strs[0]) != 255 || !strings.HasSuffix(strs[1], "IDAQAB") {
		t.Errorf("DKIM split strings = %q", strs)
	}
	if got := datas(find(t, z, "@", "TXT")); !reflect.DeepEqual(got, []string{`"google-site-verification=abc123"`, `"v=spf1 include:amazonses.com -all"`}) {
		t.Errorf("TXT = %v", got)
	}
	if www := find(t, z, "www", "CNAME")[0]; www.Data != "example.com." {
		t.Errorf("www CNAME = %q (relative value must be read as absolute)", www.Data)
	}
	api := find(t, z, "api", "A")
	if len(api) != 2 || !strings.Contains(api[0].Comment+api[1].Comment, "set-id=eu weight=70") {
		t.Errorf("api = %+v", api)
	}
}

func TestRoute53RoundTrip(t *testing.T) {
	z := parseFile(t, "testdata/route53.json", Route53, "")
	out, warns := write(t, z, Route53, WriteOptions{})
	if len(warns) > 0 {
		t.Errorf("warnings: %v", warns)
	}
	if !strings.Contains(out, `"Name": "\\052.example.com."`) {
		t.Errorf("wildcard not escaped:\n%s", out)
	}
	sameRecords(t, "route53 round trip", reparse(t, out, Route53, "").Records, z.Records)
}

func TestBINDToRoute53Change(t *testing.T) {
	z := parseFile(t, "testdata/example.zone", BIND, "")
	out, warns := write(t, z, Route53Change, WriteOptions{SkipApexNSSOA: DefaultSkipApexNSSOA(Route53Change), Route53ZoneID: "Z123"})
	if len(warns) > 0 {
		t.Errorf("warnings: %v", warns)
	}
	var batch r53ChangeBatch
	if err := json.Unmarshal([]byte(out), &batch); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(batch.Comment, "Z123") {
		t.Errorf("comment = %q", batch.Comment)
	}
	sets := map[string]r53RRSet{}
	for _, c := range batch.Changes {
		if c.Action != "UPSERT" {
			t.Errorf("action = %q", c.Action)
		}
		sets[c.ResourceRecordSet.Name+" "+c.ResourceRecordSet.Type] = c.ResourceRecordSet
	}
	if _, ok := sets["example.com. NS"]; ok {
		t.Error("apex NS not skipped")
	}
	if _, ok := sets["example.com. SOA"]; ok {
		t.Error("apex SOA not skipped")
	}
	mx := sets["example.com. MX"]
	if len(mx.ResourceRecords) != 2 || *mx.TTL != 3600 || mx.ResourceRecords[0].Value != "10 mail.example.com." {
		t.Errorf("MX set = %+v", mx)
	}
	if w := sets["*.dev.example.com. A"]; len(w.ResourceRecords) != 1 {
		t.Errorf("wildcard set = %+v", w)
	}
	if www := sets["www.example.com. CNAME"]; *www.TTL != 300 {
		t.Errorf("www TTL = %d", *www.TTL)
	}
	if len(batch.Changes) != 11 {
		t.Errorf("%d changes, want 11", len(batch.Changes))
	}
	// Change batches read back (DELETEs ignored).
	back := reparse(t, out, Route53Change, "example.com")
	if len(back.Records) != len(z.Records)-3 {
		t.Errorf("read back %d records, want %d", len(back.Records), len(z.Records)-3)
	}
	// Keeping the apex records.
	out, _ = write(t, z, Route53Change, WriteOptions{Route53Action: "create"})
	if !strings.Contains(out, `"Type": "SOA"`) || !strings.Contains(out, `"Action": "CREATE"`) {
		t.Errorf("SOA kept / CREATE expected:\n%s", out)
	}
	if err := Write(&bytes.Buffer{}, z, Route53Change, WriteOptions{Route53Action: "MERGE"}); err == nil {
		t.Error("invalid action: want error")
	}
}

func TestCloudflareToBIND(t *testing.T) {
	z := parseFile(t, "testdata/cloudflare.json", Cloudflare, "")
	out, _ := write(t, z, BIND, WriteOptions{})
	for _, want := range []string{
		"$ORIGIN example.com.",
		"@             IN A     192.0.2.1 ; cf_tags=cf-proxied:true web origin",
		"IN MX    10 mail.example.com.",
		"_sip._tcp     IN SRV   10 60 5060 sip.example.com.",
		"www           IN CNAME example.com. ; cf_tags=cf-proxied:true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	back := reparse(t, out, BIND, "")
	if a := find(t, back, "@", "A")[0]; a.Proxied == nil || !*a.Proxied || a.Comment != "web origin" {
		t.Errorf("proxied flag lost: %+v", a)
	}
}

func TestRoute53ToTerraform(t *testing.T) {
	z := parseFile(t, "testdata/route53.json", Route53, "")
	out, warns := write(t, z, Terraform, WriteOptions{SkipApexNSSOA: true})
	if len(warns) > 0 {
		t.Errorf("warnings: %v", warns)
	}
	for _, want := range []string{
		`resource "aws_route53_record" "apex_a" {`,
		"  zone_id = var.zone_id\n",
		"  alias {\n    name                   = \"d111111abcdef8.cloudfront.net.\"\n    zone_id                = \"Z2FDTNDATAQYW2\"\n    evaluate_target_health = false\n  }",
		`resource "aws_route53_record" "wildcard_a" {`,
		`  name    = "*.example.com"`,
		`records = ["google-site-verification=abc123", "v=spf1 include:amazonses.com -all"]`,
		`resource "aws_route53_record" "google_domainkey_txt" {`,
		`\"\"`, // long TXT split marker
		`resource "aws_route53_record" "api_a_2" {`,
		"weighted_routing_policy {\n    weight = 30\n  }",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, `type    = "SOA"`) || strings.Contains(out, `"NS"`) {
		t.Error("apex NS/SOA not skipped")
	}
	if strings.Count(out, "{")-strings.Count(out, "}") != 0 {
		t.Error("unbalanced braces")
	}
	out, _ = write(t, z, Terraform, WriteOptions{TerraformZoneRef: "Z0123456789ABC"})
	if !strings.Contains(out, `zone_id = "Z0123456789ABC"`) {
		t.Error("literal zone id not quoted")
	}
	out, _ = write(t, z, Terraform, WriteOptions{TerraformZoneRef: "aws_route53_zone.main.zone_id"})
	if !strings.Contains(out, `zone_id = aws_route53_zone.main.zone_id`) {
		t.Error("resource reference quoted")
	}
}

func TestTerraformCloudflare(t *testing.T) {
	z := parseFile(t, "testdata/cloudflare.json", Cloudflare, "")
	out, warns := write(t, z, TerraformCloudflare, WriteOptions{TerraformZoneRef: "var.cf_zone"})
	if len(warns) > 0 {
		t.Errorf("warnings: %v", warns)
	}
	for _, want := range []string{
		`resource "cloudflare_dns_record" "apex_a" {`,
		"  zone_id = var.cf_zone\n",
		"  proxied = true\n",
		"  ttl     = 1\n",
		"  priority = 10\n",
		"  data = {\n    port     = 5060\n    priority = 10\n    target   = \"sip.example.com\"\n    weight   = 60\n  }",
		"data = {\n    flags = 0\n    tag   = \"issue\"\n    value = \"letsencrypt.org\"\n  }",
		`  comment = "web origin"`,
		`variable "cf_zone"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestResourceNames(t *testing.T) {
	n := resourceNamer{}
	for _, c := range []struct{ name, typ, want string }{
		{"example.com.", "A", "apex_a"},
		{"example.com.", "A", "apex_a_2"},
		{"*.example.com.", "CNAME", "wildcard_cname"},
		{"_dmarc.example.com.", "TXT", "dmarc_txt"},
		{"1st.example.com.", "A", "r_1st_a"},
		{"other.org.", "NS", "other_org_ns"},
	} {
		if got := n.name(c.name, "example.com.", c.typ); got != c.want {
			t.Errorf("name(%s %s) = %q, want %q", c.name, c.typ, got, c.want)
		}
	}
}

func TestOctoDNS(t *testing.T) {
	z := parseFile(t, "testdata/octodns.yaml", OctoDNS, "example.com")
	a := find(t, z, "@", "A")
	if len(a) != 2 || a[0].TTL != 300 || a[0].Proxied == nil || !*a[0].Proxied {
		t.Errorf("A = %+v", a)
	}
	if got := find(t, z, "@", "MX")[0].Data; got != "10 mail.example.com." {
		t.Errorf("MX = %q", got)
	}
	if got := find(t, z, "_dmarc", "TXT")[0].Data; got != `"v=DMARC1; p=none"` {
		t.Errorf("DMARC = %q", got)
	}
	if got := find(t, z, "_sip._tcp", "SRV")[0].Data; got != "10 20 5060 sip.example.com." {
		t.Errorf("SRV = %q", got)
	}
	if got := find(t, z, "@", "CAA")[0].Data; got != `0 issue "letsencrypt.org"` {
		t.Errorf("CAA = %q", got)
	}
	out, warns := write(t, z, OctoDNS, WriteOptions{})
	if len(warns) > 0 {
		t.Errorf("warnings: %v", warns)
	}
	if !strings.Contains(out, `value: v=DMARC1\; p=none`) {
		t.Errorf("semicolon not escaped:\n%s", out)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, out)
	}
	sameRecords(t, "octodns round trip", reparse(t, out, OctoDNS, "example.com").Records, z.Records)

	if _, err := Parse(strings.NewReader("www: {type: A}\n"), OctoDNS, "example.com"); err == nil {
		t.Error("record without value: want error")
	}
	if _, err := Parse(strings.NewReader("www: {type: A, value: 1.2.3.4}\n"), OctoDNS, ""); err == nil {
		t.Error("no origin: want error")
	}
}

func TestOctoDNSFromRoute53(t *testing.T) {
	z := parseFile(t, "testdata/route53.json", Route53, "")
	out, warns := write(t, z, OctoDNS, WriteOptions{})
	if !strings.Contains(out, "type: ALIAS") || !strings.Contains(out, "'*':") {
		t.Errorf("octodns output:\n%s", out)
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "SOA") || !strings.Contains(joined, "routing policies") {
		t.Errorf("warnings = %v", warns)
	}
	back := reparse(t, out, OctoDNS, "example.com")
	if dkim := find(t, back, "google._domainkey", "TXT")[0]; TXTValue(dkim.Data) != TXTValue(find(t, z, "google._domainkey", "TXT")[0].Data) {
		t.Errorf("long TXT changed: %q", dkim.Data)
	}
}

func TestDNSControl(t *testing.T) {
	z := parseFile(t, "testdata/cloudflare.json", Cloudflare, "")
	z.Records = append(z.Records,
		Record{Name: "ns.example.com.", Type: "HINFO", TTL: 300, Data: `"PC" "Linux"`},
		Record{Name: "example.com.", Type: "CAA", TTL: 300, Data: `128 issue "ca.example.net"`},
	)
	out, warns := write(t, z, DNSControl, WriteOptions{})
	for _, want := range []string{
		`D("example.com", REG_NONE, DnsProvider(DSP_NONE),`,
		`A("@", "192.0.2.1", CF_PROXY_ON),`,
		`MX("@", 10, "mail.example.com.", TTL(3600)),`,
		`SRV("_sip._tcp", 10, 60, 5060, "sip.example.com."),`,
		`CAA("@", "issue", "letsencrypt.org"),`,
		"DefaultTTL(300),",
		`CAA("@", "issue", "ca.example.net", CAA_CRITICAL),`,
		`TXT("_dmarc", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),`,
		`CNAME("www", "example.com.", CF_PROXY_ON),`,
		"END);",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "HINFO") {
		t.Errorf("warnings = %v", warns)
	}
}

func TestCSVAndJSONRoundTrip(t *testing.T) {
	for _, fx := range []struct {
		path string
		f    Format
	}{{"testdata/example.zone", BIND}, {"testdata/cloudflare.json", Cloudflare}, {"testdata/route53.json", Route53}} {
		z := parseFile(t, fx.path, fx.f, "example.com")
		for _, f := range []Format{CSV, JSON} {
			out, warns := write(t, z, f, WriteOptions{})
			if len(warns) > 0 {
				t.Errorf("%s -> %s warnings: %v", fx.path, f, warns)
			}
			sameRecords(t, fx.path+" -> "+string(f), reparse(t, out, f, "").Records, z.Records)
		}
	}
	csvIn := "Name,Type,TTL,Data\nwww,A,300,192.0.2.1\n@,MX,,10 mail.example.com\n"
	z, err := Parse(strings.NewReader(csvIn), CSV, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, z, "www", "A")[0]; got.TTL != 300 {
		t.Errorf("www = %+v", got)
	}
	if got := find(t, z, "@", "MX")[0].Data; got != "10 mail.example.com." {
		t.Errorf("MX = %q", got)
	}
	if _, err := Parse(strings.NewReader("host,value\nx,y\n"), CSV, "example.com"); err == nil {
		t.Error("bad header: want error")
	}
	if _, err := Parse(strings.NewReader("name,type,ttl,data\nwww,A,abc,1.2.3.4\n"), CSV, "example.com"); err == nil {
		t.Error("bad ttl: want error")
	}
}

func TestUnsupportedTypeWarnings(t *testing.T) {
	z := &Zone{Origin: "example.com.", Records: []Record{
		{Name: "example.com.", Type: "A", TTL: 300, Data: "192.0.2.1"},
		{Name: "host.example.com.", Type: "HINFO", TTL: 300, Data: `"PC" "Linux"`},
		{Name: "loc.example.com.", Type: "LOC", TTL: 300, Data: "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m"},
		{Name: "app.example.com.", Type: AliasType, Data: "lb.example.net."},
	}}
	cases := map[Format][]string{
		Route53:             {"HINFO", "LOC", "alias target hosted zone id unknown"},
		Cloudflare:          {"HINFO", "app.example.com. ALIAS lb.example.net. written as a CNAME"},
		OctoDNS:             {"HINFO", "LOC", "written as a CNAME"},
		TerraformCloudflare: {"HINFO"},
		BIND:                {"ALIAS"},
	}
	for f, wants := range cases {
		out, warns := write(t, z, f, WriteOptions{})
		joined := strings.Join(warns, "\n")
		for _, w := range wants {
			if !strings.Contains(joined, w) {
				t.Errorf("%s: warnings %q lack %q", f, warns, w)
			}
		}
		if !strings.Contains(out, "192.0.2.1") {
			t.Errorf("%s: A record missing", f)
		}
	}
	// With the hosted zone id, an in-zone alias is expressible.
	z.Records[3].Data = "www.example.com."
	out, warns := write(t, z, Route53, WriteOptions{Route53ZoneID: "ZSELF"})
	if !strings.Contains(out, `"HostedZoneId": "ZSELF"`) || strings.Contains(strings.Join(warns, ""), "alias") {
		t.Errorf("in-zone alias: %v\n%s", warns, out)
	}
}

func TestDetect(t *testing.T) {
	read := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name string
		data []byte
		want Format
	}{
		{"example.com.zone", nil, BIND},
		{"db.example", nil, BIND},
		{"zone.yaml", nil, OctoDNS},
		{"records.csv", nil, CSV},
		{"main.tf", nil, Terraform},
		{"cloudflare.tf", nil, TerraformCloudflare},
		{"dnsconfig.js", nil, DNSControl},
		{"out.json", nil, JSON},
		{"example-route53.json", nil, Route53},
		{"route53-change.json", nil, Route53Change},
		{"cf.json", nil, Cloudflare},
		{"x.json", read("testdata/cloudflare.json"), Cloudflare},
		{"x.json", read("testdata/route53.json"), Route53},
		{"x.json", []byte(`{"Comment":"x","Changes":[]}`), Route53Change},
		{"x.json", []byte(`{"origin":"example.com.","records":[]}`), JSON},
		{"x.json", []byte(`[{"name":"a","type":"A","content":"1.2.3.4"}]`), Cloudflare},
		{"-", read("testdata/example.zone"), BIND},
		{"-", read("testdata/octodns.yaml"), OctoDNS},
		{"-", read("testdata/cloudflare.json"), Cloudflare},
		{"-", []byte("name,type,ttl,data\n"), CSV},
		{"export.txt", []byte("example.com.\t300\tIN\tA\t192.0.2.1\n"), BIND},
	}
	for _, c := range cases {
		got, err := Detect(c.name, c.data)
		if err != nil || got != c.want {
			t.Errorf("Detect(%q) = %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	for _, c := range []struct {
		name string
		data []byte
	}{{"notes", nil}, {"x.json", []byte(`{"foo":1}`)}, {"x.json", []byte(`{`)}, {"-", []byte("hello world")}} {
		if f, err := Detect(c.name, c.data); err == nil {
			t.Errorf("Detect(%q, %q) = %q, want error", c.name, c.data, f)
		}
	}
}

func TestFormats(t *testing.T) {
	if len(Formats()) != 10 || Formats()[0] != BIND {
		t.Errorf("Formats() = %v", Formats())
	}
	for _, f := range Formats() {
		if !CanWrite(f) {
			t.Errorf("CanWrite(%s) = false", f)
		}
		if got, err := ParseFormat(strings.ToUpper(string(f))); err != nil || got != f {
			t.Errorf("ParseFormat(%s) = %v, %v", f, got, err)
		}
	}
	for _, f := range []Format{Terraform, TerraformCloudflare, DNSControl} {
		if CanRead(f) {
			t.Errorf("CanRead(%s) = true", f)
		}
		if _, err := Parse(strings.NewReader(""), f, "example.com"); err == nil {
			t.Errorf("Parse(%s): want error", f)
		}
	}
	if CanRead("nope") || CanWrite("nope") {
		t.Error("unknown format readable/writable")
	}
	if _, err := ParseFormat("nope"); err == nil {
		t.Error("ParseFormat(nope): want error")
	}
	if f, _ := ParseFormat("tf"); f != Terraform {
		t.Errorf("alias tf = %s", f)
	}
}

func TestNormalizeLookupRRs(t *testing.T) {
	z := &Zone{Origin: "Example.COM", Records: []Record{
		{Name: "WWW", Type: "cname", Data: "@"},
		{Name: "@", Type: "mx", TTL: 300, Data: "10   mail"},
		{Name: "example.com.", Type: "MX", TTL: 600, Data: "10 mail.example.com."}, // duplicate
		{Name: "@", Type: "txt", Data: "unquoted text"},
		{Name: "app", Type: AliasType, Data: "lb.example.net."},
		{Name: "@", Type: "SOA", Data: "ns1 hostmaster 1 2 3 4 5"},
	}}
	z.Normalize()
	if z.Origin != "example.com." {
		t.Errorf("origin = %q", z.Origin)
	}
	want := []Record{
		{Name: "example.com.", Type: "SOA", Data: "ns1.example.com. hostmaster.example.com. 1 2 3 4 5"},
		{Name: "example.com.", Type: "MX", TTL: 300, Data: "10 mail.example.com."},
		{Name: "example.com.", Type: "TXT", Data: `"unquoted text"`},
		{Name: "app.example.com.", Type: AliasType, Data: "lb.example.net."},
		{Name: "www.example.com.", Type: "CNAME", Data: "example.com."},
	}
	sameRecords(t, "normalize", z.Records, want)
	if got := z.Names(); !reflect.DeepEqual(got, []string{"example.com.", "app.example.com.", "www.example.com."}) {
		t.Errorf("Names = %v", got)
	}
	if got := z.Lookup("WWW", "cname"); len(got) != 1 {
		t.Errorf("Lookup(WWW) = %v", got)
	}
	if got := z.Lookup("@", ""); len(got) != 3 {
		t.Errorf("Lookup(@, any) = %v", got)
	}
	rrs, err := z.RRs()
	if err != nil || len(rrs) != 4 {
		t.Fatalf("RRs = %v, %v", rrs, err)
	}
	if mx, ok := rrs[1].(*dns.MX); !ok || mx.Mx != "mail.example.com." || mx.Hdr.Ttl != 300 {
		t.Errorf("rr[1] = %v", rrs[1])
	}
	back := FromRRs("", rrs)
	if back.Origin != "example.com." || len(back.Records) != 4 {
		t.Errorf("FromRRs = %+v", back)
	}
	bad := &Zone{Origin: "example.com.", Records: []Record{{Name: "x.example.com.", Type: "A", Data: "nope"}}}
	if _, err := bad.RRs(); err == nil {
		t.Error("RRs with bad data: want error")
	}
	c := z.Clone()
	c.Records[0].Name = "changed."
	if z.Records[0].Name == "changed." {
		t.Error("Clone shares records")
	}
	if n := z.CountByType()["MX"]; n != 1 {
		t.Errorf("CountByType MX = %d", n)
	}
}

func TestTXTHelpers(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`"a b" "c"`, []string{"a b", "c"}},
		{`"say \"hi\"\; ok"`, []string{`say "hi"; ok`}},
		{`"tab\009x"`, []string{"tab\tx"}},
		{`plain text`, []string{"plain text"}},
		{`""`, []string{""}},
	} {
		if got := TXTStrings(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("TXTStrings(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := QuoteTXT([]string{`say "hi"`, "a\\b"}); got != `"say \"hi\"" "a\\b"` {
		t.Errorf("QuoteTXT = %s", got)
	}
	long := strings.Repeat("x", 600)
	if got := splitLong([]string{long}); len(got) != 3 || len(got[0]) != 255 || len(got[2]) != 90 {
		t.Errorf("splitLong lens wrong: %d", len(got))
	}
	if got := DecodeRoute53Name(`\052.example.com.`); got != "*.example.com." {
		t.Errorf("DecodeRoute53Name = %q", got)
	}
}

func TestWriteEmptyZone(t *testing.T) {
	z := &Zone{Origin: "empty.example."}
	for _, f := range Formats() {
		if _, err := WriteWithWarnings(&bytes.Buffer{}, z, f, WriteOptions{}); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := WriteWithWarnings(&bytes.Buffer{}, nil, BIND, WriteOptions{}); err == nil {
		t.Error("nil zone: want error")
	}
}
