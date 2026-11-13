package lookup_test

import (
	"context"
	"dlookup/lookup"
	"strings"
	"testing"
	"time"
)

const rdapDomainJSON = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited", "client transfer prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00+02:00"},
    {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:34Z"}
  ],
  "nameservers": [{"objectClassName":"nameserver","ldhName":"B.IANA-SERVERS.NET"},{"objectClassName":"nameserver","ldhName":"A.IANA-SERVERS.NET"}],
  "secureDNS": {"delegationSigned": true},
  "entities": [{
    "objectClassName": "entity",
    "handle": "376",
    "roles": ["registrar"],
    "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]],
    "entities": [{
      "objectClassName": "entity",
      "roles": ["abuse"],
      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", ""], ["email", {}, "text", "abuse@registrar.example"]]]
    }]
  }]
}`

const rdapIPJSON = `{
  "objectClassName": "ip network",
  "handle": "NET-192-0-2-0-1",
  "startAddress": "192.0.2.0",
  "endAddress": "192.0.2.255",
  "ipVersion": "v4",
  "name": "TEST-NET-1",
  "type": "IANA Special Use",
  "country": "US",
  "status": ["active"],
  "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
  "events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}],
  "entities": [{
    "roles": ["registrant"],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Internet Assigned Numbers Authority"], ["adr", {}, "text", ["", "", "12025 Waterfront Drive", "Los Angeles", "CA", "90094", "US"]]]]
  }]
}`

func rdapExec(t *testing.T, target string) (string, error) {
	t.Helper()
	p, ok := lookup.GetProvider("RDAP")
	if !ok {
		t.Fatal("RDAP provider not registered")
	}
	return p.Execute(context.Background(), target, lookup.Options{Timeout: 5 * time.Second})
}

func TestRDAPProvider_Static(t *testing.T) {
	p, ok := lookup.GetProviderByFlagName("rdap")
	if !ok || p.Name() != "RDAP" || p.Command() != "" || !p.CheckAvailability() {
		t.Fatalf("RDAP provider misconfigured: %v %v", ok, p)
	}
}

func TestRDAPProvider_Domain(t *testing.T) {
	startRDAPServer(t, map[string]string{"domain/example.com": rdapDomainJSON})

	// "www." is stripped after a 404; case is normalised.
	for _, target := range []string{"example.com", "WWW.Example.com."} {
		out, err := rdapExec(t, target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		for _, want := range []string{
			"Domain:       EXAMPLE.COM",
			"Registrar:    Example Registrar, Inc. (IANA ID 376)",
			"Status:       client delete prohibited, client transfer prohibited",
			"Created:      1995-08-14 04:00:00 UTC",
			"Expires:      2030-08-13 02:00:00 UTC",
			"Updated:      2024-08-14 07:01:34 UTC",
			"Nameservers:  a.iana-servers.net, b.iana-servers.net",
			"DNSSEC:       signed",
			"Abuse:        abuse@registrar.example",
			"Source:       http://",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output missing %q:\n%s", target, want, out)
			}
		}
	}
}

func TestRDAPProvider_IP(t *testing.T) {
	startRDAPServer(t, map[string]string{"ip/192.0.2.1": rdapIPJSON})
	out, err := rdapExec(t, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Network:      TEST-NET-1",
		"Handle:       NET-192-0-2-0-1",
		"Range:        192.0.2.0 - 192.0.2.255",
		"CIDR:         192.0.2.0/24",
		"Country:      US",
		"Organization: Internet Assigned Numbers Authority",
		"Created:      2010-01-01 00:00:00 UTC",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRDAPProvider_Errors(t *testing.T) {
	startRDAPServer(t, nil)

	if _, err := rdapExec(t, "missing.com"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing domain: err = %v", err)
	}
	if _, err := rdapExec(t, "example.zz"); err == nil || !strings.Contains(err.Error(), "no RDAP service") {
		t.Errorf("unknown TLD: err = %v", err)
	}
	if _, err := rdapExec(t, "198.51.100.1"); err == nil || !strings.Contains(err.Error(), "no RDAP service") {
		t.Errorf("unknown IP range: err = %v", err)
	}
	if _, err := rdapExec(t, "-x"); err == nil {
		t.Error("invalid target: expected error")
	}
}
