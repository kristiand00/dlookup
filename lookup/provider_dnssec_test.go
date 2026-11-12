package lookup

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var dnssecTestNow = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func fixedNow(t *testing.T, now time.Time) {
	t.Helper()
	old := chkNow
	chkNow = func() time.Time { return now }
	t.Cleanup(func() { chkNow = old })
}

type signedZone struct {
	ksk, zsk         *dns.DNSKEY
	kskPriv, zskPriv crypto.Signer
	soa              dns.RR
}

func newKey(t *testing.T, flags uint16, alg uint8, bits int) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: flags, Protocol: 3, Algorithm: alg,
	}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatal(err)
	}
	return k, priv.(crypto.Signer)
}

func sign(t *testing.T, key *dns.DNSKEY, priv crypto.Signer, rrset []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
		Algorithm:  key.Algorithm,
		SignerName: key.Hdr.Name,
		KeyTag:     key.KeyTag(),
		Inception:  uint32(inception.Unix()),
		Expiration: uint32(expiration.Unix()),
	}
	if err := sig.Sign(priv, rrset); err != nil {
		t.Fatal(err)
	}
	return sig
}

// dnssecWorld builds a delegated example.test signed with a KSK and ZSK.
// mutate may adjust the records before they are installed.
type dnssecSetup struct {
	alg            uint8
	bits           int
	keySigExpiry   time.Time
	soaSigExpiry   time.Time
	ds             func(z *signedZone) []dns.RR // DS records at the parent
	noKeys         bool
	extra          []string // extra child records (e.g. NSEC3PARAM)
	extraNegatives []string
}

func dnssecRun(t *testing.T, s dnssecSetup) string {
	t.Helper()
	fixedNow(t, dnssecTestNow)
	if s.alg == 0 {
		s.alg, s.bits = dns.ECDSAP256SHA256, 256
	}
	if s.keySigExpiry.IsZero() {
		s.keySigExpiry = dnssecTestNow.Add(30 * 24 * time.Hour)
	}
	if s.soaSigExpiry.IsZero() {
		s.soaSigExpiry = dnssecTestNow.Add(20 * 24 * time.Hour)
	}
	inception := dnssecTestNow.Add(-14 * 24 * time.Hour)

	w := newWorld(t, nil, append(append([]string(nil), childRecords...), s.extra...), nil)
	z := &signedZone{}
	z.ksk, z.kskPriv = newKey(t, 257, s.alg, s.bits)
	z.zsk, z.zskPriv = newKey(t, 256, s.alg, s.bits)
	soa := w.ns1.owned("example.test.", dns.TypeSOA)
	var childRRs []dns.RR
	if !s.noKeys {
		keys := []dns.RR{z.ksk, z.zsk}
		childRRs = append(childRRs, keys...)
		childRRs = append(childRRs, sign(t, z.ksk, z.kskPriv, keys, inception, s.keySigExpiry))
		childRRs = append(childRRs, sign(t, z.zsk, z.zskPriv, soa, inception, s.soaSigExpiry))
	}
	for _, f := range []*fakeDNS{w.ns1, w.ns2} {
		f.addRR(childRRs...)
		f.add(t, s.extraNegatives...)
	}
	if s.ds != nil {
		w.parent.addRR(s.ds(z)...)
	}
	out, err := (&DNSSECProvider{}).Execute(context.Background(), "example.test", w.opts)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func goodDS(z *signedZone) []dns.RR { return []dns.RR{z.ksk.ToDS(dns.SHA256)} }

func TestDNSSECValid(t *testing.T) {
	out := dnssecRun(t, dnssecSetup{
		ds:    goodDS,
		extra: []string{"example.test. 0 IN NSEC3PARAM 1 0 0 -"},
	})
	mustContain(t, out,
		"DS at parent (from test nameserver a.nic.test (192.0.2.53)):",
		"DNSKEY (from ns1.example.test (198.51.100.1)):",
		"KSK  ECDSAP256SHA256",
		"ZSK  ECDSAP256SHA256",
		"matches a DNSKEY (ECDSAP256SHA256, SHA256)",
		"✓ DNSKEY RRset signed by key",
		"valid until 2026-12-12 12:00 UTC (30 days left)",
		"✓ SOA signed by key",
		"✓ algorithm: ECDSAP256SHA256",
		"✓ NSEC3, 0 iterations, no salt",
		"0 warnings, 0 problems",
	)
}

func TestDNSSECExpiredAndExpiring(t *testing.T) {
	out := dnssecRun(t, dnssecSetup{
		ds:           goodDS,
		keySigExpiry: dnssecTestNow.Add(3 * 24 * time.Hour),
		soaSigExpiry: dnssecTestNow.Add(-time.Hour),
	})
	mustContain(t, out,
		"! DNSKEY RRset signature by key",
		"expires soon: valid until 2026-11-15 12:00 UTC (3 days left)",
		"✗ SOA: signature by key",
		"EXPIRED 2026-11-12 11:00 UTC",
	)
}

func TestDNSSECBrokenChains(t *testing.T) {
	out := dnssecRun(t, dnssecSetup{ds: func(z *signedZone) []dns.RR {
		ds := z.ksk.ToDS(dns.SHA256)
		ds.Digest = "00" + ds.Digest[2:]
		return []dns.RR{ds}
	}})
	mustContain(t, out, "✗ broken chain: no DS matches any DNSKEY")

	out = dnssecRun(t, dnssecSetup{noKeys: true, ds: func(z *signedZone) []dns.RR { return goodDS(z) }})
	mustContain(t, out, "✗ broken chain: DS at the parent but no DNSKEY in the zone")

	out = dnssecRun(t, dnssecSetup{})
	mustContain(t, out, "! zone is signed but the parent has no DS")

	out = dnssecRun(t, dnssecSetup{noKeys: true})
	mustContain(t, out, "! not signed (no DS at the parent, no DNSKEY)", "0 ok, 1 warning, 0 problems")

	// A stale extra DS next to a good one, with a SHA-1 digest.
	out = dnssecRun(t, dnssecSetup{ds: func(z *signedZone) []dns.RR {
		stale := z.zsk.ToDS(dns.SHA1)
		stale.KeyTag++
		return []dns.RR{z.ksk.ToDS(dns.SHA1), stale}
	}})
	mustContain(t, out, "uses the SHA-1 digest (deprecated", "matches no DNSKEY (stale DS")
	mustNotContain(t, out, "broken chain")
}

func TestDNSSECDeprecatedAlgAndNSEC(t *testing.T) {
	out := dnssecRun(t, dnssecSetup{
		alg: dns.RSASHA1, bits: 1024, ds: goodDS,
		extraNegatives: []string{"example.test. 600 IN NSEC www.example.test. A NS SOA RRSIG NSEC DNSKEY"},
	})
	mustContain(t, out,
		"KSK  RSASHA1            1024 bits",
		"! deprecated algorithm: RSASHA1",
		"✓ NSEC (zone contents can be enumerated",
	)

	out = dnssecRun(t, dnssecSetup{ds: goodDS, extra: []string{"example.test. 0 IN NSEC3PARAM 1 0 10 abcd"}})
	mustContain(t, out, "! NSEC3, 10 iterations, salt abcd (RFC 9276")
}

func TestDNSSECVerifyUnknownKey(t *testing.T) {
	k, priv := newKey(t, 256, dns.ECDSAP256SHA256, 256)
	other, _ := newKey(t, 256, dns.ECDSAP256SHA256, 256)
	soa, _ := dns.NewRR("example.test. 300 IN SOA ns. h. 1 2 3 4 5")
	sig := sign(t, k, priv, []dns.RR{soa}, dnssecTestNow.Add(-time.Hour), dnssecTestNow.Add(time.Hour))
	res := dnssecVerify([]dns.RR{soa}, []*dns.RRSIG{sig}, []*dns.DNSKEY{other}, dnssecTestNow)
	if res.valid || res.problem == "" {
		t.Errorf("unexpected %+v", res)
	}
	// Tampered data does not verify.
	soa2, _ := dns.NewRR("example.test. 300 IN SOA ns. h. 2 2 3 4 5")
	res = dnssecVerify([]dns.RR{soa2}, []*dns.RRSIG{sig}, []*dns.DNSKEY{k}, dnssecTestNow)
	if res.valid {
		t.Errorf("tampered RRset verified")
	}
	res = dnssecVerify([]dns.RR{soa}, []*dns.RRSIG{sig}, []*dns.DNSKEY{k}, dnssecTestNow)
	if !res.valid {
		t.Errorf("valid signature rejected: %+v", res)
	}
}

func TestDNSSECShortWindowNoWarning(t *testing.T) {
	// Online signers use ~2-day windows: 1 day left is normal.
	var r chkReport
	k, priv := newKey(t, 256, dns.ECDSAP256SHA256, 256)
	soa, _ := dns.NewRR("example.test. 300 IN SOA ns. h. 1 2 3 4 5")
	sig := sign(t, k, priv, []dns.RR{soa}, dnssecTestNow.Add(-24*time.Hour), dnssecTestNow.Add(24*time.Hour))
	dnssecSigCheck(&r, "SOA", []dns.RR{soa}, []*dns.RRSIG{sig}, []*dns.DNSKEY{k}, dnssecTestNow)
	mustContain(t, r.String(), "✓ SOA signed by key", "(24h left)")
}
