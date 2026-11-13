package lookup

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSSECProvider checks a zone's DNSSEC chain: DS at the parent, DNSKEY and
// signatures at the child, algorithms and authenticated denial (NSEC/NSEC3).
type DNSSECProvider struct{}

func (p *DNSSECProvider) Name() string     { return "DNSSEC" }
func (p *DNSSECProvider) FlagName() string { return "dnssec-check" }
func (p *DNSSECProvider) Usage() string {
	return "Run DNSSEC (DS/DNSKEY chain, signature validity, algorithms, NSEC/NSEC3) on domains from <filename>"
}
func (p *DNSSECProvider) Command() string         { return "" }
func (p *DNSSECProvider) CheckAvailability() bool { return true }
func (p *DNSSECProvider) DomainOnly() bool        { return true }

// dnssecExpiryWarning is how close to expiry a signature triggers a warning
// (capped at a quarter of the signature's validity window).
const dnssecExpiryWarning = 7 * 24 * time.Hour

// dnssecDeprecated lists algorithms that must not be used for signing
// (RFC 8624).
var dnssecDeprecated = map[uint8]bool{
	dns.RSAMD5: true, dns.DSA: true, dns.RSASHA1: true, dns.DSANSEC3SHA1: true,
	dns.RSASHA1NSEC3SHA1: true, dns.ECCGOST: true,
}

func dnssecAlgName(a uint8) string {
	if s, ok := dns.AlgorithmToString[a]; ok {
		return s
	}
	return fmt.Sprintf("algorithm %d", a)
}

func dnssecDigestName(d uint8) string {
	if s, ok := dns.HashToString[d]; ok {
		return s
	}
	return fmt.Sprintf("digest %d", d)
}

func dnssecSigs(rrs []dns.RR, covered uint16) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range rrs {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == covered {
			out = append(out, s)
		}
	}
	return out
}

// dnssecSigResult is the outcome of validating one RRset.
type dnssecSigResult struct {
	valid     bool
	keyTag    uint16
	inception time.Time
	expires   time.Time
	problem   string
}

// dnssecVerify validates rrset with any of sigs made by one of keys. It
// returns the valid signature expiring last, or the most relevant problem.
func dnssecVerify(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time) dnssecSigResult {
	if len(rrset) == 0 {
		return dnssecSigResult{problem: "no records to validate"}
	}
	if len(sigs) == 0 {
		return dnssecSigResult{problem: "no RRSIG"}
	}
	var best dnssecSigResult
	var problems []string
	for _, sig := range sigs {
		var key *dns.DNSKEY
		for _, k := range keys {
			if k.KeyTag() == sig.KeyTag && k.Algorithm == sig.Algorithm && strings.EqualFold(k.Hdr.Name, sig.SignerName) {
				key = k
				break
			}
		}
		exp := time.Unix(int64(sig.Expiration), 0).UTC()
		switch {
		case key == nil:
			problems = append(problems, fmt.Sprintf("signature by key %d, which is not in the DNSKEY set", sig.KeyTag))
		case sig.Verify(key, rrset) != nil:
			problems = append(problems, fmt.Sprintf("signature by key %d does not verify: %v", sig.KeyTag, sig.Verify(key, rrset)))
		case !sig.ValidityPeriod(now):
			if now.After(exp) {
				problems = append(problems, fmt.Sprintf("signature by key %d EXPIRED %s", sig.KeyTag, exp.Format("2006-01-02 15:04 UTC")))
			} else {
				problems = append(problems, fmt.Sprintf("signature by key %d not valid before %s", sig.KeyTag, time.Unix(int64(sig.Inception), 0).UTC().Format("2006-01-02 15:04 UTC")))
			}
		default:
			if !best.valid || exp.After(best.expires) {
				best = dnssecSigResult{valid: true, keyTag: sig.KeyTag, expires: exp,
					inception: time.Unix(int64(sig.Inception), 0).UTC()}
			}
		}
	}
	if best.valid {
		return best
	}
	return dnssecSigResult{problem: strings.Join(problems, "; ")}
}

func (p *DNSSECProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, err := chkDomain(target, "DNSSEC")
	if err != nil {
		return "", err
	}
	if err := chkPrepare(opts); err != nil {
		return "", err
	}
	var r chkReport
	zone, zerr := chkZoneOf(ctx, opts, name)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if zerr != nil {
		r.line("DNSSEC for %s", strings.TrimSuffix(name, "."))
		r.section("Checks:")
		r.bad("%v", zerr)
		return r.String(), nil
	}
	if zone != name {
		r.line("%s is not a zone apex; checking its zone %s", chkShow(name), chkShow(zone))
	}

	// DS from the parent's servers.
	ref := chkGetReferral(ctx, opts, zone)
	var dsAns chkAnswer
	dsFrom := "resolver"
	if ref.Err == nil && len(ref.ParentServers) > 0 {
		dsAns = chkAtAny(ctx, opts, chkAllQueryAddrs(ref.ParentServers), zone, dns.TypeDS, true)
		dsFrom = chkShow(ref.Parent) + " nameserver " + chkServerName(ref.ParentServers, dsAns.server)
	}
	if dsAns.msg == nil || dsAns.msg.Rcode != dns.RcodeSuccess {
		dsAns = chkRecursiveDO(ctx, opts, zone, dns.TypeDS)
		dsFrom = "resolver"
	}

	// DNSKEY, SOA and denial from the zone's own servers.
	hosts := chkAuthServers(ctx, opts, zone, ref)
	childAddrs := chkAllQueryAddrs(hosts)
	usedResolver := false
	childQuery := func(qname string, qtype uint16) chkAnswer {
		if len(childAddrs) > 0 {
			a := chkAtAny(ctx, opts, childAddrs, qname, qtype, true)
			if a.msg != nil && (a.msg.Rcode == dns.RcodeSuccess || a.msg.Rcode == dns.RcodeNameError) {
				return a
			}
		}
		if qtype == dns.TypeDNSKEY {
			usedResolver = true
		}
		return chkRecursiveDO(ctx, opts, qname, qtype)
	}
	keyAns := childQuery(zone, dns.TypeDNSKEY)
	soaAns := childQuery(zone, dns.TypeSOA)
	paramAns := childQuery(zone, dns.TypeNSEC3PARAM)
	denialAns := childQuery("dlookup-nx-7d1c."+zone, dns.TypeA)
	if err := ctx.Err(); err != nil {
		return "", err
	}

	parent := ref.Parent
	if parent == "" {
		parent = "?"
	}
	r.line("DNSSEC for %s (parent zone %s)", chkShow(zone), chkShow(parent))

	var dss []*dns.DS
	for _, rr := range dsAns.records(zone, dns.TypeDS) {
		dss = append(dss, rr.(*dns.DS))
	}
	var keys []*dns.DNSKEY
	var keyRRs []dns.RR
	for _, rr := range keyAns.records(zone, dns.TypeDNSKEY) {
		keys = append(keys, rr.(*dns.DNSKEY))
		keyRRs = append(keyRRs, rr)
	}

	r.section("DS at parent (from %s):", dsFrom)
	switch {
	case dsAns.problem() != "" && len(dss) == 0:
		r.line("  (lookup failed: %s)", dsAns.problem())
	case len(dss) == 0:
		r.line("  (none)")
	}
	for _, ds := range dss {
		digest := strings.ToLower(ds.Digest)
		if len(digest) > 16 {
			digest = digest[:16] + "…"
		}
		r.line("  %5d  %-18s %-8s %s", ds.KeyTag, dnssecAlgName(ds.Algorithm), dnssecDigestName(ds.DigestType), digest)
	}
	keyFrom := "resolver"
	if !usedResolver && keyAns.server != "" {
		keyFrom = chkServerName(hosts, keyAns.server)
	}
	r.section("DNSKEY (from %s):", keyFrom)
	if len(keys) == 0 {
		if p := keyAns.problem(); p != "" {
			r.line("  (lookup failed: %s)", p)
		} else {
			r.line("  (none)")
		}
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].Flags > keys[j].Flags })
	for _, k := range keys {
		role := "ZSK"
		if k.Flags&dns.SEP != 0 {
			role = "KSK"
		}
		if k.Flags&dns.REVOKE != 0 {
			role += " (revoked)"
		}
		r.line("  %5d  %-4s %-18s %s", k.KeyTag(), role, dnssecAlgName(k.Algorithm), dnssecKeySize(k))
	}

	r.section("Checks:")
	if keyAns.msg == nil && len(dss) == 0 {
		r.bad("could not query DNSKEY: %s", keyAns.problem())
		return r.String(), nil
	}
	switch {
	case len(dss) == 0 && len(keys) == 0:
		r.warn("not signed (no DS at the parent, no DNSKEY): answers cannot be validated")
		return r.String(), nil
	case len(dss) > 0 && len(keys) == 0:
		r.bad("broken chain: DS at the parent but no DNSKEY in the zone — validating resolvers return SERVFAIL")
		return r.String(), nil
	case len(dss) == 0:
		r.warn("zone is signed but the parent has no DS: the chain of trust is not established (insecure)")
	}

	// DS -> KSK.
	if len(dss) > 0 {
		matched := 0
		for _, ds := range dss {
			ok := false
			for _, k := range keys {
				if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm {
					continue
				}
				if calc := k.ToDS(ds.DigestType); calc != nil && strings.EqualFold(calc.Digest, ds.Digest) {
					ok = true
					break
				}
			}
			if ok {
				matched++
				r.ok("DS %d matches a DNSKEY (%s, %s)", ds.KeyTag, dnssecAlgName(ds.Algorithm), dnssecDigestName(ds.DigestType))
				if ds.DigestType == dns.SHA1 {
					r.warn("DS %d uses the SHA-1 digest (deprecated; publish SHA-256)", ds.KeyTag)
				}
			} else if len(dss) > 1 {
				r.warn("DS %d matches no DNSKEY (stale DS from an old key?)", ds.KeyTag)
			}
		}
		if matched == 0 {
			r.bad("broken chain: no DS matches any DNSKEY — validating resolvers return SERVFAIL")
		}
	}

	now := chkNow()
	dnssecSigCheck(&r, "DNSKEY RRset", keyRRs, dnssecSigs(keyAns.msg.Answer, dns.TypeDNSKEY), keys, now)
	var soaRRs []dns.RR
	var soaSigs []*dns.RRSIG
	if soaAns.msg != nil {
		soaRRs = soaAns.records(zone, dns.TypeSOA)
		soaSigs = dnssecSigs(soaAns.msg.Answer, dns.TypeSOA)
	}
	dnssecSigCheck(&r, "SOA", soaRRs, soaSigs, keys, now)

	// Algorithms.
	algs := map[uint8]bool{}
	for _, k := range keys {
		algs[k.Algorithm] = true
	}
	var names, deprecated []string
	for a := range algs {
		names = append(names, dnssecAlgName(a))
		if dnssecDeprecated[a] {
			deprecated = append(deprecated, dnssecAlgName(a))
		}
	}
	sort.Strings(names)
	sort.Strings(deprecated)
	if len(deprecated) > 0 {
		r.warn("deprecated algorithm%s: %s (RFC 8624; roll to ECDSAP256SHA256 or ED25519)", plural(len(deprecated), "", "s"), strings.Join(deprecated, ", "))
	} else {
		r.ok("algorithm%s: %s", plural(len(names), "", "s"), strings.Join(names, ", "))
	}

	// Authenticated denial.
	dnssecDenial(&r, zone, paramAns, denialAns)
	return r.String(), nil
}

func dnssecSigCheck(r *chkReport, what string, rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time) {
	if len(rrset) == 0 {
		r.bad("%s: not found", what)
		return
	}
	res := dnssecVerify(rrset, sigs, keys, now)
	if !res.valid {
		r.bad("%s: %s", what, res.problem)
		return
	}
	left := res.expires.Sub(now)
	until := fmt.Sprintf("valid until %s (%s)", res.expires.Format("2006-01-02 15:04 UTC"), dnssecLeft(left))
	// Online signers (e.g. Cloudflare) use windows of a day or two and
	// re-sign constantly: warn only in the last quarter of short windows.
	threshold := dnssecExpiryWarning
	if w := res.expires.Sub(res.inception) / 4; w < threshold {
		threshold = w
	}
	if left < threshold {
		r.warn("%s signature by key %d expires soon: %s", what, res.keyTag, until)
		return
	}
	r.ok("%s signed by key %d, %s", what, res.keyTag, until)
}

func dnssecLeft(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%d days left", int(d.Hours()/24))
	}
	return fmt.Sprintf("%dh left", int(d.Hours()))
}

func dnssecDenial(r *chkReport, zone string, paramAns, denialAns chkAnswer) {
	var param *dns.NSEC3PARAM
	for _, rr := range paramAns.records(zone, dns.TypeNSEC3PARAM) {
		param = rr.(*dns.NSEC3PARAM)
	}
	var nsec3 *dns.NSEC3
	nsec := false
	if denialAns.msg != nil {
		for _, rr := range denialAns.msg.Ns {
			switch v := rr.(type) {
			case *dns.NSEC3:
				nsec3 = v
			case *dns.NSEC:
				nsec = true
			}
		}
	}
	iterations, salt := -1, ""
	switch {
	case param != nil:
		iterations, salt = int(param.Iterations), param.Salt
	case nsec3 != nil:
		iterations, salt = int(nsec3.Iterations), nsec3.Salt
	}
	switch {
	case iterations >= 0:
		desc := fmt.Sprintf("NSEC3, %d iteration%s", iterations, plural(iterations, "", "s"))
		if salt != "" && salt != "-" {
			desc += ", salt " + strings.ToLower(salt)
		} else {
			desc += ", no salt"
		}
		if iterations > 0 {
			r.warn("%s (RFC 9276: use 0 iterations; resolvers may treat high counts as insecure)", desc)
		} else if salt != "" && salt != "-" {
			r.ok("%s (RFC 9276 recommends no salt)", desc)
		} else {
			r.ok("%s", desc)
		}
	case nsec:
		r.ok("NSEC (zone contents can be enumerated by walking the NSEC chain)")
	default:
		r.warn("no NSEC/NSEC3 proof in a negative answer (denial of existence could not be checked)")
	}
}

func dnssecKeySize(k *dns.DNSKEY) string {
	switch k.Algorithm {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		pk := dnssecRSABits(k.PublicKey)
		if pk > 0 {
			return fmt.Sprintf("%d bits", pk)
		}
	}
	return ""
}

// dnssecRSABits returns the modulus size of an RFC 3110 RSA public key.
func dnssecRSABits(b64 string) int {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil || len(raw) < 3 {
		return 0
	}
	explen := int(raw[0])
	off := 1
	if explen == 0 {
		if len(raw) < 3 {
			return 0
		}
		explen = int(raw[1])<<8 | int(raw[2])
		off = 3
	}
	modlen := len(raw) - off - explen
	if modlen <= 0 {
		return 0
	}
	mod := raw[off+explen:]
	bits := modlen * 8
	for _, c := range mod {
		if c != 0 {
			for m := byte(0x80); m > 0 && c&m == 0; m >>= 1 {
				bits--
			}
			break
		}
		bits -= 8
	}
	return bits
}

func dnssecHost(server string) string {
	if h, _, err := net.SplitHostPort(server); err == nil {
		return h
	}
	if server == "" {
		return "resolver"
	}
	return server
}

func init() {
	RegisterProvider(&DNSSECProvider{})
}
