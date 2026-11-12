package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dlookup/lookup"
	"dlookup/zonefile"
)

// stubDumpZone replaces dumpZone for the duration of the test.
func stubDumpZone(t *testing.T, fn func(context.Context, lookup.ZoneDumpOptions) (*zonefile.Zone, string, error)) {
	t.Helper()
	old := dumpZone
	dumpZone = fn
	t.Cleanup(func() { dumpZone = old })
}

func cannedZone() *zonefile.Zone {
	z := &zonefile.Zone{Origin: "example.com.", Records: []zonefile.Record{
		{Name: "example.com.", Type: "SOA", TTL: 3600, Data: "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"},
		{Name: "example.com.", Type: "NS", TTL: 3600, Data: "ns1.example.com."},
		{Name: "example.com.", Type: "A", TTL: 300, Data: "192.0.2.1"},
		{Name: "example.com.", Type: "MX", TTL: 300, Data: "10 mail.example.com."},
		{Name: "www.example.com.", Type: "CNAME", TTL: 300, Data: "example.com."},
	}}
	z.Normalize()
	return z
}

const testZoneFile = `$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1 hostmaster 1 7200 3600 1209600 300
     IN NS  ns1
     IN A   192.0.2.1
     IN MX  10 mail
www  IN CNAME @
host IN HINFO "PC" "Linux"
`

func runZoneCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"zone"}, args...), strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func writeZoneTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestZoneCLIUsageAndHelp(t *testing.T) {
	cases := []struct {
		args []string
		code int
		want string // in stdout+stderr
	}{
		{nil, zoneExitUsage, "dlookup zone convert"},
		{[]string{"--help"}, zoneExitOK, "Usage:"},
		{[]string{"bogus"}, zoneExitUsage, `unknown zone command "bogus"`},
		{[]string{"convert", "--help"}, zoneExitOK, "-keep-apex-ns"},
		{[]string{"export", "-h"}, zoneExitOK, "-no-axfr"},
		{[]string{"show", "--help"}, zoneExitOK, "--origin"},
		{[]string{"convert"}, zoneExitUsage, "exactly one input file"},
		{[]string{"convert", "a", "b"}, zoneExitUsage, "exactly one input file"},
		{[]string{"convert", "x.zone", "--to", "nope"}, zoneExitUsage, "unknown format"},
		{[]string{"convert", "x.zone", "-o", "out.unknown"}, zoneExitUsage, "use --to"},
		{[]string{"convert", "x.tf", "--from", "terraform"}, zoneExitUsage, "can only be written"},
		{[]string{"convert", "--bogus", "x"}, zoneExitUsage, "flag provided but not defined"},
		{[]string{"export"}, zoneExitUsage, "exactly one domain"},
		{[]string{"export", "not a domain!"}, zoneExitUsage, "Error"},
		{[]string{"export", "example.com", "--server", "bad server!"}, zoneExitUsage, "--server"},
		{[]string{"formats", "extra"}, zoneExitUsage, "no arguments"},
	}
	for _, c := range cases {
		code, out, errOut := runZoneCmd(t, "", c.args...)
		if code != c.code || !strings.Contains(out+errOut, c.want) {
			t.Errorf("zone %v: code %d (want %d), output %q lacks %q", c.args, code, c.code, out+errOut, c.want)
		}
	}
}

func TestZoneCLIFormats(t *testing.T) {
	code, out, _ := runZoneCmd(t, "", "formats")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{"FORMAT", "route53-change", "terraform-cloudflare", "dnscontrol", "cf-proxied"} {
		if !strings.Contains(out, want) {
			t.Errorf("formats output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "terraform ") && !strings.Contains(line, " -  ") {
			t.Errorf("terraform should not be readable: %q", line)
		}
	}
}

func TestZoneCLIConvertFiles(t *testing.T) {
	in := writeZoneTemp(t, "example.com.zone", testZoneFile)
	out := filepath.Join(filepath.Dir(in), "sub", "changes.route53-change.json")
	code, stdout, stderr := runZoneCmd(t, "", "convert", in, "-o", out, "--zone-id", "Z1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "bind → route53-change") || !strings.Contains(stderr, "Warning: route53-change: skipped host.example.com. HINFO") {
		t.Errorf("stderr = %q", stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Comment string
		Changes []struct {
			Action            string
			ResourceRecordSet struct{ Name, Type string }
		}
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(batch.Comment, "Z1") || len(batch.Changes) != 3 {
		t.Errorf("batch = %+v", batch)
	}
	for _, c := range batch.Changes {
		if c.ResourceRecordSet.Type == "NS" || c.ResourceRecordSet.Type == "SOA" {
			t.Errorf("apex %s not skipped", c.ResourceRecordSet.Type)
		}
	}
	// --keep-apex-ns keeps them.
	code, _, _ = runZoneCmd(t, "", "convert", in, "-o", out, "--keep-apex-ns")
	data, _ = os.ReadFile(out)
	if code != 0 || !strings.Contains(string(data), `"Type": "SOA"`) {
		t.Errorf("--keep-apex-ns: code %d\n%s", code, data)
	}
}

func TestZoneCLIConvertStdinStdout(t *testing.T) {
	cf := `{"result":[{"zone_name":"example.org","name":"example.org","type":"A","content":"192.0.2.7","proxied":true,"ttl":1},
	{"zone_name":"example.org","name":"example.org","type":"MX","content":"mx.example.org","priority":5,"ttl":300}]}`
	code, out, errOut := runZoneCmd(t, cf, "convert", "-")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	for _, want := range []string{"$ORIGIN example.org.", "IN A  192.0.2.7 ; cf_tags=cf-proxied:true", "IN MX 5 mx.example.org."} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if errOut != "" {
		t.Errorf("stderr = %q", errOut)
	}
	// BIND from stdin needs --origin when it has no $ORIGIN.
	code, out, _ = runZoneCmd(t, "www 300 IN A 192.0.2.9\n", "convert", "-", "--from", "bind", "--origin", "example.net", "--to", "csv")
	if code != 0 || !strings.Contains(out, "www.example.net.,A,300,192.0.2.9") {
		t.Errorf("csv: code %d\n%s", code, out)
	}
	code, out, _ = runZoneCmd(t, "www 300 IN A 192.0.2.9\n", "convert", "-", "--from", "bind", "--origin", "example.net", "--to", "terraform", "--tf-zone", "aws_route53_zone.main.zone_id")
	if code != 0 || !strings.Contains(out, "zone_id = aws_route53_zone.main.zone_id") {
		t.Errorf("terraform: code %d\n%s", code, out)
	}
}

func TestZoneCLIConvertErrors(t *testing.T) {
	code, _, errOut := runZoneCmd(t, "", "convert", filepath.Join(t.TempDir(), "missing.zone"))
	if code != zoneExitRuntime || !strings.Contains(errOut, "no such file") {
		t.Errorf("missing file: code %d %q", code, errOut)
	}
	bad := writeZoneTemp(t, "bad.zone", "$ORIGIN example.com.\nwww IN A not-an-ip\n")
	code, _, errOut = runZoneCmd(t, "", "convert", bad, "--to", "json")
	if code != zoneExitRuntime || !strings.Contains(errOut, "bad.zone") {
		t.Errorf("parse error: code %d %q", code, errOut)
	}
	code, _, errOut = runZoneCmd(t, "hello there", "convert", "-")
	if code != zoneExitRuntime || !strings.Contains(errOut, "--from") {
		t.Errorf("undetectable: code %d %q", code, errOut)
	}
}

func TestZoneCLIShow(t *testing.T) {
	in := writeZoneTemp(t, "example.com.zone", testZoneFile)
	code, out, errOut := runZoneCmd(t, "", "show", in)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	for _, want := range []string{"Zone example.com", "NAME", "www   3600  CNAME  example.com.", "6 records, 3 names: A 1, CNAME 1, HINFO 1, MX 1, NS 1, SOA 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
}

func TestZoneCLIExport(t *testing.T) {
	var got lookup.ZoneDumpOptions
	stubDumpZone(t, func(ctx context.Context, o lookup.ZoneDumpOptions) (*zonefile.Zone, string, error) {
		got = o
		return cannedZone(), "probe (42 names)", nil
	})
	dir := t.TempDir()
	out := filepath.Join(dir, "example.com.yaml")
	code, stdout, errOut := runZoneCmd(t, "", "export", "Example.COM", "-o", out, "--server", "192.0.2.53", "--names", "shop, vpn", "--no-axfr")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if got.Domain != "example.com" || got.Server != "192.0.2.53" || got.TryAXFR || strings.Join(got.ExtraNames, "|") != "shop|vpn" {
		t.Errorf("dump options = %+v", got)
	}
	if stdout != "" || !strings.Contains(errOut, "via probe (42 names)") || !strings.Contains(errOut, "may be incomplete") || !strings.Contains(errOut, "Saved octodns") {
		t.Errorf("stdout %q stderr %q", stdout, errOut)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "www:") {
		t.Errorf("octodns file:\n%s", data)
	}

	// AXFR to stdout: no incompleteness warning; default format BIND.
	stubDumpZone(t, func(ctx context.Context, o lookup.ZoneDumpOptions) (*zonefile.Zone, string, error) {
		if !o.TryAXFR {
			t.Error("AXFR should be tried by default")
		}
		return cannedZone(), "axfr from ns1.example.com", nil
	})
	code, stdout, errOut = runZoneCmd(t, "", "export", "example.com")
	if code != 0 || !strings.Contains(stdout, "$ORIGIN example.com.") || strings.Contains(errOut, "incomplete") {
		t.Errorf("axfr: code %d stdout %q stderr %q", code, stdout, errOut)
	}

	stubDumpZone(t, func(ctx context.Context, o lookup.ZoneDumpOptions) (*zonefile.Zone, string, error) {
		return nil, "", errors.New("no nameservers")
	})
	code, _, errOut = runZoneCmd(t, "", "export", "example.com", "--to", "json")
	if code != zoneExitRuntime || !strings.Contains(errOut, "no nameservers") {
		t.Errorf("dump error: code %d %q", code, errOut)
	}
}
