package lookup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"dlookup/zonefile"
)

// Zone diff: compare the records served by two DNS servers for one domain,
// e.g. the current provider and a new one before switching the NS delegation.
//
// Enumeration. DNS has no "list all names" query, so names are found by:
//   - AXFR (zone transfer), when ZoneDiffOptions.TryAXFR is set: tried against
//     the old servers, then the new one; if both allow it the names are merged.
//     Every owner name in the transfer is checked. With Types == nil the types
//     checked at a name are DefaultZoneDiffTypes plus every type found at that
//     name in the transfer (e.g. PTR, TLSA, HTTPS), except DNSSEC records
//     (RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, CDS, CDNSKEY) and ZONEMD, which a
//     new provider re-signs and which would only add noise. With explicit Types
//     only those types are checked.
//   - Otherwise probing: the apex, a built-in list of common labels, DKIM
//     selectors, SRV names, a random label (to detect a "*" wildcard, reported
//     as "*.<domain>"), plus ExtraNames.
//   - In both modes in-zone CNAME/MX/NS/SRV targets found in answers are added
//     and checked too, repeatedly, up to maxZoneDiffNames names.
//
// To keep query counts sane, SOA is only queried at the apex, SRV only at
// "_service._proto" names, and only TXT/CNAME at other "_" names (_dmarc,
// DKIM "_domainkey" names, ...). A name that is NXDOMAIN on both sides is not
// queried for further types, and (name, type) pairs absent on both sides are
// not reported.
//
// Queries are sent with RD=1, which works against authoritative-only servers
// (they ignore it) as well as against recursive resolvers. Only records owned
// by the queried name and of the queried type are compared, so CNAME chains
// followed by a recursive server do not produce noise. For NS, a referral
// (NS in the authority section owned by the queried name) counts as the
// answer, so delegations to sub-zones are compared too.
//
// Comparison: rdata is normalised (names lower-cased, TXT character-strings
// joined, TTL dropped unless CompareTTL), de-duplicated and compared as sets.
// The SOA serial is always ignored; SOA mname/rname and apex NS differences
// are reported as changed with an explanatory Note, since they usually differ
// between providers.
//
// Zone files. Either side can be a parsed zone file (ZoneDiffOptions.OldZone /
// NewZone) instead of a server: that side's answers come from the file, and
// every name and type in the file is checked (plus ExtraNames, plus the probe
// list when Probe is set; AXFR is still tried against server sides). With an
// old zone file and neither NewServer nor NewZone, the file is compared with
// the domain's live authoritative nameservers. Names below a delegation in a
// file (glue) are not compared. Route 53 ALIAS records (type ALIAS or ANAME)
// are compared by the addresses their target resolves to (in-zone targets
// from the file, others via the system resolvers; unresolvable targets are
// shown as "ALIAS <target>"). Cloudflare proxied records differ from live
// answers served by Cloudflare (anycast addresses, flattened CNAMEs); such
// differences are marked Expected. A file without SOA or apex NS records
// (common in provider exports) does not make those differences count.

// DiffStatus classifies one (name, type) comparison.
type DiffStatus int

const (
	DiffMatch   DiffStatus = iota // same on both
	DiffChanged                   // present on both, different data
	DiffMissing                   // on old, absent on new
	DiffExtra                     // absent on old, present on new
	DiffError                     // query failed on either side
)

var diffStatusNames = [...]string{"match", "changed", "missing", "extra", "error"}

// AllDiffStatuses lists every status in display order.
var AllDiffStatuses = []DiffStatus{DiffMatch, DiffChanged, DiffMissing, DiffExtra, DiffError}

func (s DiffStatus) String() string {
	if s >= 0 && int(s) < len(diffStatusNames) {
		return diffStatusNames[s]
	}
	return fmt.Sprintf("DiffStatus(%d)", int(s))
}

// MarshalText encodes the status as its String form (also used for JSON and
// as JSON map keys).
func (s DiffStatus) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a status produced by MarshalText.
func (s *DiffStatus) UnmarshalText(b []byte) error {
	for i, n := range diffStatusNames {
		if n == string(b) {
			*s = DiffStatus(i)
			return nil
		}
	}
	return fmt.Errorf("unknown diff status %q", b)
}

// ZoneDiffOptions configures DiffZone.
type ZoneDiffOptions struct {
	Domain      string
	OldServer   string                // "" = discover the domain's authoritative NS and query those
	NewServer   string                // required; IP, host, or host:port. Hostnames are resolved.
	ExtraNames  []string              // extra names to check (relative "shop" or FQDN)
	Types       []uint16              // nil = DefaultZoneDiffTypes
	CompareTTL  bool                  // default false: ignore TTLs
	TryAXFR     bool                  // attempt zone transfer for enumeration
	Timeout     time.Duration         // per query; 0 = DefaultTimeout
	Concurrency int                   // 0 = 8
	Progress    func(done, total int) // optional, may be called from goroutines

	// OldZone, when set, replaces the old servers: old answers come from the
	// file (OldServer must be empty). With NewServer empty and NewZone nil the
	// new side is the domain's live authoritative nameservers.
	OldZone *zonefile.Zone
	// NewZone, when set, replaces the new server (NewServer must be empty).
	NewZone *zonefile.Zone
	// OldZoneLabel / NewZoneLabel name the files in results (e.g. the path).
	OldZoneLabel, NewZoneLabel string
	// Probe also checks the common-name probe list when a zone file is used
	// (without files, probing is the fallback when AXFR is unavailable).
	Probe bool
}

// DefaultZoneDiffTypes are the record types compared when ZoneDiffOptions.Types is nil.
var DefaultZoneDiffTypes = []uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS,
	dns.TypeTXT, dns.TypeSOA, dns.TypeCAA, dns.TypeSRV,
}

// RecordDiff is the comparison result for one (name, type).
type RecordDiff struct {
	Name   string     `json:"name"` // FQDN, lowercase, trailing dot
	Type   string     `json:"type"` // "A", "MX", ...
	Status DiffStatus `json:"status"`
	Old    []string   `json:"old"` // normalized rdata strings, sorted
	New    []string   `json:"new"`
	Err    string     `json:"error,omitempty"`
	Note   string     `json:"note,omitempty"` // e.g. "SOA serial ignored", "apex NS expected to differ"
	// Expected marks a change that is normal when moving to a new provider
	// (apex NS, SOA primary NS/contact); it does not count for HasDifferences.
	Expected bool `json:"expected,omitempty"`
}

// ZoneDiffResult is the outcome of DiffZone.
type ZoneDiffResult struct {
	Domain     string   `json:"domain"`
	OldServers []string `json:"old_servers"` // actually queried; empty for a zone file
	NewServer  string   `json:"new_server"`  // resolved addr:port; empty for a zone file
	// NewServers lists all new servers when they were discovered (the domain's
	// live authoritative nameservers); NewServer is the first working one.
	NewServers []string `json:"new_servers,omitempty"`
	OldFile    string   `json:"old_file,omitempty"` // label of the old zone file, if any
	NewFile    string   `json:"new_file,omitempty"` // label of the new zone file, if any
	// Enumeration: "axfr from old", "axfr from new", "axfr from old and new"
	// or "probe (N names)"; with zone files e.g. "file (N records)",
	// "old file (N records) + new file (M records)", "file (N records) + axfr
	// from new + probe (K names)".
	Enumeration string             `json:"enumeration"`
	Records     []RecordDiff       `json:"records"` // sorted by name then type
	Counts      map[DiffStatus]int `json:"counts"`
	Warnings    []string           `json:"warnings,omitempty"` // e.g. unparseable zone file records
}

// HasDifferences reports whether any record is changed, missing, extra or
// errored, ignoring changes marked Expected.
func (r *ZoneDiffResult) HasDifferences() bool {
	if r == nil {
		return false
	}
	for _, rd := range r.Records {
		if rd.Status != DiffMatch && !rd.Expected {
			return true
		}
	}
	return false
}

const (
	maxZoneDiffNames          = 500
	defaultZoneDiffConcurrent = 8
)

// Test hooks.
var (
	// zoneDiscoveryServers returns the resolvers used to find the zone's NS.
	zoneDiscoveryServers = SystemDNSServers
	// resolveHost resolves a hostname to IP addresses (system resolver).
	resolveHost = func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	// zoneNSPort is the port used for discovered authoritative nameservers.
	zoneNSPort = "53"
)

// probeLabels are checked (relative to the domain) when AXFR is unavailable.
var probeLabels = []string{
	"www", "mail", "smtp", "imap", "pop", "webmail", "ftp", "api", "app", "cdn",
	"m", "blog", "shop", "dev", "staging", "vpn", "remote", "autodiscover",
	"autoconfig", "mx", "ns1", "ns2", "_dmarc", "_mta-sts", "mta-sts",
	"_domainkey",
	"_autodiscover._tcp", "_sip._tls", "_sipfederationtls._tcp", "_caldavs._tcp",
	"_carddavs._tcp", "_imaps._tcp", "_submission._tcp", "_xmpp-client._tcp",
}

var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail"}

var noiseTypes = map[uint16]bool{
	dns.TypeRRSIG: true, dns.TypeNSEC: true, dns.TypeNSEC3: true, dns.TypeNSEC3PARAM: true,
	dns.TypeDNSKEY: true, dns.TypeCDS: true, dns.TypeCDNSKEY: true, dns.TypeZONEMD: true,
	dns.TypeOPT: true, dns.TypeTSIG: true, dns.TypeAXFR: true, dns.TypeIXFR: true,
}

// zoneSide is one side of a diff: DNS servers or a zone file.
type zoneSide struct {
	servers    []string // resolved addr:port, when not a file
	file       *fileZone
	discovered bool // servers are the domain's authoritative nameservers
}

type zoneDiffer struct {
	opts       ZoneDiffOptions
	zone       string // FQDN, lowercase
	types      []uint16
	allowFound bool // add types found via AXFR / zone files
	timeout    time.Duration
	old, new   *zoneSide
	foundTypes map[string]map[uint16]bool // name -> types found in transfers and files
	wildcard   string                     // random probe name, reported as "*.<zone>"
	maxNames   int
}

// online reports whether any side is a DNS server (so ALIAS targets outside
// the zone may be resolved).
func (d *zoneDiffer) online() bool {
	return (d.old != nil && d.old.file == nil) || (d.new != nil && d.new.file == nil)
}

// DiffZone compares the records for opts.Domain served by the old and new
// servers (or held in the old/new zone files).
// It returns an error only for invalid options or when a server cannot be
// reached at all; per-record failures are reported as DiffError records.
func DiffZone(ctx context.Context, opts ZoneDiffOptions) (*ZoneDiffResult, error) {
	rawDomain := opts.Domain
	if strings.TrimSpace(rawDomain) == "" {
		for _, z := range []*zonefile.Zone{opts.OldZone, opts.NewZone} {
			if z != nil && strings.TrimSpace(z.Origin) != "" {
				rawDomain = z.Origin
				break
			}
		}
	}
	domain, err := NormalizeTarget(rawDomain)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(domain) != nil {
		return nil, fmt.Errorf("invalid domain %q: an IP address is not a zone", opts.Domain)
	}
	if opts.OldZone != nil && strings.TrimSpace(opts.OldServer) != "" {
		return nil, errors.New("old server and old zone file are mutually exclusive")
	}
	if opts.NewZone != nil && strings.TrimSpace(opts.NewServer) != "" {
		return nil, errors.New("new server and new zone file are mutually exclusive")
	}
	if opts.NewZone == nil && opts.OldZone == nil && strings.TrimSpace(opts.NewServer) == "" {
		return nil, errors.New("new server is required")
	}
	if opts.NewServer != "" {
		if err := ValidateServer(opts.NewServer); err != nil {
			return nil, err
		}
	}
	if opts.OldServer != "" {
		if err := ValidateServer(opts.OldServer); err != nil {
			return nil, err
		}
	}

	d := &zoneDiffer{
		opts:       opts,
		zone:       dns.Fqdn(domain),
		types:      opts.Types,
		allowFound: opts.Types == nil,
		timeout:    opts.Timeout,
		old:        &zoneSide{},
		new:        &zoneSide{},
	}
	if d.types == nil {
		d.types = DefaultZoneDiffTypes
	}
	if d.timeout <= 0 {
		d.timeout = DefaultTimeout
	}

	res := &ZoneDiffResult{Domain: d.zone, Counts: map[DiffStatus]int{}}
	for _, f := range []struct {
		z     *zonefile.Zone
		side  *zoneSide
		label string
		which string
		dst   *string
	}{
		{opts.OldZone, d.old, opts.OldZoneLabel, "old", &res.OldFile},
		{opts.NewZone, d.new, opts.NewZoneLabel, "new", &res.NewFile},
	} {
		if f.z == nil {
			continue
		}
		fz, warnings, err := newFileZone(f.z, d.zone)
		if err != nil {
			return nil, fmt.Errorf("%s zone file: %w", f.which, err)
		}
		for _, w := range warnings {
			res.Warnings = append(res.Warnings, f.which+" zone file: "+w)
		}
		f.side.file = fz
		*f.dst = f.label
		if *f.dst == "" {
			*f.dst = "zone file"
		}
	}

	extra := make([]string, 0, len(opts.ExtraNames))
	for _, n := range opts.ExtraNames {
		q, err := qualifyName(n, d.zone)
		if err != nil {
			return nil, err
		}
		extra = append(extra, q)
	}

	if d.new.file == nil {
		if opts.NewServer != "" {
			s, err := resolveServer(ctx, opts.NewServer)
			if err != nil {
				return nil, fmt.Errorf("new server: %w", err)
			}
			d.new.servers = []string{s}
		} else {
			// Old zone file vs the live zone.
			if d.new.servers, err = d.discoverServers(ctx); err != nil {
				return nil, err
			}
			d.new.discovered = true
		}
	}
	if d.old.file == nil {
		if opts.OldServer != "" {
			s, err := resolveServer(ctx, opts.OldServer)
			if err != nil {
				return nil, fmt.Errorf("old server: %w", err)
			}
			d.old.servers = []string{s}
		} else {
			if d.old.servers, err = d.discoverServers(ctx); err != nil {
				return nil, err
			}
			d.old.discovered = true
		}
	}

	// Reachability check; also moves the first working server to the front.
	for _, s := range []struct {
		side  *zoneSide
		which string
	}{{d.old, "old"}, {d.new, "new"}} {
		if s.side.file != nil {
			continue
		}
		used, err := d.checkServer(ctx, s.side.servers)
		if err != nil {
			return nil, fmt.Errorf("%s server %s: %w", s.which, strings.Join(s.side.servers, ", "), err)
		}
		s.side.servers = moveToFront(s.side.servers, used)
	}

	if d.old.file == nil {
		res.OldServers = append([]string(nil), d.old.servers...)
	}
	if d.new.file == nil {
		res.NewServer = d.new.servers[0]
		if d.new.discovered {
			res.NewServers = append([]string(nil), d.new.servers...)
		}
	}

	names, enumeration, probing := d.enumerate(ctx, extra)
	diffs, total, err := d.diffAll(ctx, names)
	if err != nil {
		return nil, err
	}
	if probing && enumeration == "" {
		enumeration = fmt.Sprintf("probe (%d names)", total)
	}
	res.Enumeration = enumeration
	sortRecordDiffs(diffs)
	res.Records = diffs
	for _, s := range AllDiffStatuses {
		res.Counts[s] = 0
	}
	for _, r := range diffs {
		res.Counts[r.Status]++
	}
	return res, nil
}

// enumerate returns the names to check and a description of how they were
// found. probing is true when only the probe list (and no file or transfer)
// was used; the caller then reports the total number of names checked.
func (d *zoneDiffer) enumerate(ctx context.Context, extra []string) (names []string, enumeration string, probing bool) {
	d.foundTypes = map[string]map[uint16]bool{}
	set := map[string]bool{}
	var parts []string

	files := 0
	for _, s := range []*zoneSide{d.old, d.new} {
		if s.file != nil {
			files++
		}
	}
	for _, s := range []struct {
		side  *zoneSide
		which string
	}{{d.old, "old "}, {d.new, "new "}} {
		f := s.side.file
		if f == nil {
			continue
		}
		label := "file"
		if files == 2 {
			label = s.which + "file"
		}
		parts = append(parts, fmt.Sprintf("%s (%d records)", label, f.count))
		mergeTypes(d.foundTypes, f.types)
		for n := range f.types {
			set[n] = true
		}
	}

	if d.opts.TryAXFR {
		var from []string
		for _, s := range []struct {
			side  *zoneSide
			which string
		}{{d.old, "old"}, {d.new, "new"}} {
			if s.side.file != nil {
				continue
			}
			if found, err := axfrTransfer(ctx, s.side.servers, d.zone, d.timeout); err == nil {
				from = append(from, s.which)
				mergeTypes(d.foundTypes, found)
				for n := range found {
					set[n] = true
				}
			}
		}
		if len(from) > 0 {
			parts = append(parts, "axfr from "+strings.Join(from, " and "))
			set[d.zone] = true
		}
	}

	names = make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)

	switch {
	case len(parts) == 0:
		// Neither a file nor a transfer: probe.
		names = d.probeNames()
		probing = true
	case files > 0 && d.opts.Probe:
		probe := d.probeNames()
		if set["*."+d.zone] {
			// The file lists the wildcard itself; don't report it twice.
			probe = probe[:len(probe)-1]
			d.wildcard = ""
		}
		parts = append(parts, fmt.Sprintf("probe (%d names)", len(probe)))
		names = append(names, probe...)
	}
	if !probing {
		enumeration = strings.Join(parts, " + ")
	}
	d.maxNames = maxZoneDiffNames + len(names)
	return append(names, extra...), enumeration, probing
}

// diffAll diffs every name (and in-zone names discovered in answers).
func (d *zoneDiffer) diffAll(ctx context.Context, names []string) ([]RecordDiff, int, error) {
	var (
		mu    sync.Mutex
		diffs []RecordDiff
	)
	total, err := d.run(ctx, names, func(ctx context.Context, name string) []string {
		rd, more := d.diffName(ctx, name)
		mu.Lock()
		diffs = append(diffs, rd...)
		mu.Unlock()
		return more
	})
	if err != nil {
		return nil, 0, err
	}
	return diffs, total, nil
}

func mergeTypes(dst, src map[string]map[uint16]bool) {
	for n, ts := range src {
		if dst[n] == nil {
			dst[n] = map[uint16]bool{}
		}
		for t := range ts {
			dst[n][t] = true
		}
	}
}

func moveToFront(list []string, s string) []string {
	out := []string{s}
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// qualifyName turns a relative ("shop", "@") or absolute name into a
// lowercase FQDN inside zone. Names without a trailing dot are relative to the
// zone unless they already end with the zone name.
func qualifyName(name, zone string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return zone, nil
	}
	abs := strings.HasSuffix(name, ".")
	check := strings.TrimSuffix(name, ".")
	wild := false
	if check == "*" {
		return "*." + zone, nil
	}
	if strings.HasPrefix(check, "*.") {
		wild, check = true, check[2:]
	}
	norm, err := NormalizeTarget(check)
	if err != nil {
		return "", fmt.Errorf("invalid name %q: %w", name, err)
	}
	if net.ParseIP(norm) != nil {
		return "", fmt.Errorf("invalid name %q: IP address", name)
	}
	fq := dns.Fqdn(norm)
	if !abs && fq != zone && !strings.HasSuffix(fq, "."+zone) {
		fq = norm + "." + zone
	}
	if wild {
		fq = "*." + fq
	}
	return fq, nil
}

// resolveServer turns "host[:port]" into "ip:port" (port defaults to 53).
func resolveServer(ctx context.Context, server string) (string, error) {
	addr := serverAddr(server)
	host, port, _ := net.SplitHostPort(addr)
	if net.ParseIP(host) != nil {
		return addr, nil
	}
	ips, err := resolveHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", host, err)
	}
	ips = preferIPv4(ips)
	if len(ips) == 0 {
		return "", fmt.Errorf("resolving %s: no addresses", host)
	}
	return net.JoinHostPort(ips[0], port), nil
}

func preferIPv4(ips []string) []string {
	var v4, v6 []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	return append(v4, v6...)
}

// discoverServers finds the authoritative nameservers of the zone
// containing d.zone (walking up via SOA if d.zone itself has no NS) and
// returns their addresses, IPv4 first.
func (d *zoneDiffer) discoverServers(ctx context.Context) ([]string, error) {
	resolvers := zoneDiscoveryServers()
	resp, _, err := queryServers(ctx, resolvers, d.zone, dns.TypeNS, d.timeout)
	if err != nil {
		return nil, fmt.Errorf("discovering nameservers for %s: %w", d.zone, err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, fmt.Errorf("discovering nameservers for %s: domain does not exist (NXDOMAIN)", d.zone)
	}
	apex := d.zone
	hosts := ownedNS(resp, apex)
	if len(hosts) == 0 {
		// Not a zone apex: find the enclosing zone via SOA.
		soaResp, _, err := queryServers(ctx, resolvers, d.zone, dns.TypeSOA, d.timeout)
		if err != nil {
			return nil, fmt.Errorf("discovering zone apex for %s: %w", d.zone, err)
		}
		apex = ""
		for _, rr := range append(append([]dns.RR(nil), soaResp.Answer...), soaResp.Ns...) {
			if soa, ok := rr.(*dns.SOA); ok {
				apex = strings.ToLower(soa.Hdr.Name)
				break
			}
		}
		if apex == "" {
			return nil, fmt.Errorf("could not find the zone apex for %s", d.zone)
		}
		resp, _, err = queryServers(ctx, resolvers, apex, dns.TypeNS, d.timeout)
		if err != nil {
			return nil, fmt.Errorf("discovering nameservers for %s: %w", apex, err)
		}
		hosts = ownedNS(resp, apex)
		if len(hosts) == 0 {
			return nil, fmt.Errorf("no NS records found for %s", apex)
		}
	}

	glue := map[string][]string{}
	for _, rr := range resp.Extra {
		name := strings.ToLower(rr.Header().Name)
		switch v := rr.(type) {
		case *dns.A:
			glue[name] = append(glue[name], v.A.String())
		case *dns.AAAA:
			glue[name] = append(glue[name], v.AAAA.String())
		}
	}
	var v4, v6 []string
	seen := map[string]bool{}
	var lastErr error
	for _, h := range hosts {
		ips := glue[h]
		if len(ips) == 0 {
			ips, err = resolveHost(ctx, strings.TrimSuffix(h, "."))
			if err != nil {
				lastErr = err
				continue
			}
		}
		for _, ip := range ips {
			p := net.ParseIP(ip)
			if p == nil || seen[ip] {
				continue
			}
			seen[ip] = true
			addr := net.JoinHostPort(ip, zoneNSPort)
			if p.To4() != nil {
				v4 = append(v4, addr)
			} else {
				v6 = append(v6, addr)
			}
		}
	}
	out := append(v4, v6...)
	if len(out) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no addresses")
		}
		return nil, fmt.Errorf("resolving nameservers of %s (%s): %w", apex, strings.Join(hosts, ", "), lastErr)
	}
	return out, nil
}

func ownedNS(resp *dns.Msg, owner string) []string {
	var hosts []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, owner) {
			hosts = append(hosts, strings.ToLower(ns.Ns))
		}
	}
	sort.Strings(hosts)
	return hosts
}

// checkServer verifies one of servers answers an SOA query for the zone and
// returns the server that did.
func (d *zoneDiffer) checkServer(ctx context.Context, servers []string) (string, error) {
	_, used, err := queryServers(ctx, servers, d.zone, dns.TypeSOA, d.timeout)
	return used, err
}

// queryServers sends one query to each server in turn until one returns a
// usable answer (NOERROR or NXDOMAIN). Network errors and other rcodes
// (SERVFAIL, REFUSED, ...) move on to the next server; the last error is
// returned if none answers.
func queryServers(ctx context.Context, servers []string, name string, qtype uint16, timeout time.Duration) (*dns.Msg, string, error) {
	var lastErr error
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		m.RecursionDesired = true
		m.SetEdns0(4096, false)
		resp, err := exchange(ctx, timeout, m, server)
		if err != nil {
			lastErr = fmt.Errorf("query to %s failed: %w", server, err)
			continue
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			lastErr = &DNSError{Name: name, Type: dns.TypeToString[qtype], Rcode: dns.RcodeToString[resp.Rcode], Server: server}
			continue
		}
		return resp, server, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers")
	}
	return nil, "", lastErr
}

// axfrTransfer attempts a zone transfer from each server in turn and returns
// the owner names (inside zone) and their record types.
func axfrTransfer(ctx context.Context, servers []string, zone string, timeout time.Duration) (map[string]map[uint16]bool, error) {
	rrs, _, err := axfrRecords(ctx, servers, zone, timeout)
	if err != nil {
		return nil, err
	}
	found := map[string]map[uint16]bool{}
	for _, rr := range rrs {
		h := rr.Header()
		name := strings.ToLower(h.Name)
		if found[name] == nil {
			found[name] = map[uint16]bool{}
		}
		found[name][h.Rrtype] = true
	}
	return found, nil
}

// axfrRecords attempts a zone transfer from each server in turn and returns
// the in-zone records (without DNSSEC/transfer noise types; the SOA once) and
// the server that answered.
func axfrRecords(ctx context.Context, servers []string, zone string, timeout time.Duration) ([]dns.RR, string, error) {
	var lastErr error
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		rrs, err := axfrOne(ctx, server, zone, timeout)
		if err == nil {
			return rrs, server, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers")
	}
	return nil, "", lastErr
}

func axfrOne(ctx context.Context, server, zone string, timeout time.Duration) ([]dns.RR, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	t := &dns.Transfer{Conn: &dns.Conn{Conn: conn}, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	m := new(dns.Msg)
	m.SetAxfr(zone)
	ch, err := t.In(m, server)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var out []dns.RR
	var xerr error
	sawSOA := false
	for env := range ch {
		if env.Error != nil {
			xerr = env.Error
			continue
		}
		for _, rr := range env.RR {
			h := rr.Header()
			name := strings.ToLower(h.Name)
			if h.Rrtype == dns.TypeSOA && name == zone {
				if sawSOA {
					continue // the closing SOA
				}
				sawSOA = true
			}
			if noiseTypes[h.Rrtype] || !inZone(name, zone) {
				continue
			}
			out = append(out, rr)
		}
	}
	if xerr != nil {
		return nil, xerr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !sawSOA {
		return nil, errors.New("zone transfer returned no SOA")
	}
	return out, nil
}

func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// probeNames returns the names checked when no zone transfer is available.
func (d *zoneDiffer) probeNames() []string {
	names := []string{d.zone}
	for _, l := range probeLabels {
		names = append(names, l+"."+d.zone)
	}
	for _, s := range dkimSelectors {
		names = append(names, s+"._domainkey."+d.zone)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	d.wildcard = "dlookup-wildcard-probe-" + hex.EncodeToString(b[:]) + "." + d.zone
	return append(names, d.wildcard)
}

// typesFor returns the record types to query at name.
func (d *zoneDiffer) typesFor(name string) []uint16 {
	labels := dns.SplitDomainName(name)
	var allowed func(t uint16) bool
	switch {
	case len(labels) >= 2 && strings.HasPrefix(labels[0], "_") &&
		(labels[1] == "_tcp" || labels[1] == "_udp" || labels[1] == "_tls" || labels[1] == "_sctp"):
		allowed = func(t uint16) bool { return t == dns.TypeSRV || t == dns.TypeCNAME }
	case len(labels) >= 1 && strings.HasPrefix(labels[0], "_"),
		containsLabel(labels, "_domainkey"):
		allowed = func(t uint16) bool { return t == dns.TypeTXT || t == dns.TypeCNAME }
	default:
		apex := name == d.zone
		allowed = func(t uint16) bool {
			if t == dns.TypeSRV {
				return false
			}
			return t != dns.TypeSOA || apex
		}
	}
	var out []uint16
	seen := map[uint16]bool{}
	for _, t := range d.types {
		if allowed(t) && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	// Types found at this name in a zone transfer or file are always checked.
	var found []uint16
	for t := range d.foundTypes[name] {
		if seen[t] || noiseTypes[t] {
			continue
		}
		if !d.allowFound && !containsType(d.types, t) {
			continue
		}
		if t == dns.TypeSOA && name != d.zone {
			continue
		}
		found = append(found, t)
	}
	sort.Slice(found, func(i, j int) bool { return found[i] < found[j] })
	return append(out, found...)
}

func containsLabel(labels []string, l string) bool {
	for _, x := range labels {
		if x == l {
			return true
		}
	}
	return false
}

func containsType(ts []uint16, t uint16) bool {
	for _, x := range ts {
		if x == t {
			return true
		}
	}
	return false
}

// run visits names (and in-zone names returned by visit) with a bounded
// worker pool, calling visit concurrently. It returns the total number of
// names visited.
func (d *zoneDiffer) run(ctx context.Context, initial []string, visit func(ctx context.Context, name string) []string) (int, error) {
	workers := d.opts.Concurrency
	if workers <= 0 {
		workers = defaultZoneDiffConcurrent
	}
	limit := d.maxNames
	if limit <= 0 {
		limit = maxZoneDiffNames
	}
	seen := map[string]bool{}
	var pending []string
	add := func(n string) {
		if !seen[n] && len(seen) < limit {
			seen[n] = true
			pending = append(pending, n)
		}
	}
	for _, n := range initial {
		add(n)
	}

	var (
		mu   sync.Mutex
		done int
	)
	for len(pending) > 0 {
		batch := pending
		pending = nil
		var found []string
		jobs := make(chan string)
		var wg sync.WaitGroup
		for i := 0; i < workers && i < len(batch); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for name := range jobs {
					more := visit(ctx, name)
					mu.Lock()
					found = append(found, more...)
					done++
					if d.opts.Progress != nil {
						d.opts.Progress(done, len(seen))
					}
					mu.Unlock()
				}
			}()
		}
	feed:
		for _, n := range batch {
			select {
			case jobs <- n:
			case <-ctx.Done():
				break feed
			}
		}
		close(jobs)
		wg.Wait()
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		mu.Lock()
		sort.Strings(found)
		for _, n := range found {
			add(n)
		}
		mu.Unlock()
	}
	return len(seen), nil
}

// sideAnswer is one side's answer for (name, type).
type sideAnswer struct {
	rrs   []dns.RR // owned by the queried name, of the queried type
	nx    bool     // name does not exist
	err   error
	extra []string // pseudo values compared as-is (unresolved "ALIAS <target>")
	alias []string // ALIAS targets this answer was resolved from
	note  string
}

func (d *zoneDiffer) query(ctx context.Context, servers []string, name string, qtype uint16) sideAnswer {
	resp, _, err := queryServers(ctx, servers, name, qtype, d.timeout)
	if err != nil {
		return sideAnswer{err: err}
	}
	var a sideAnswer
	ownsAny := false
	for _, rr := range resp.Answer {
		h := rr.Header()
		if !strings.EqualFold(h.Name, name) {
			continue
		}
		ownsAny = true
		if h.Rrtype == qtype {
			a.rrs = append(a.rrs, rr)
		}
	}
	if qtype == dns.TypeNS && len(a.rrs) == 0 && name != d.zone {
		// Referral to a delegated sub-zone.
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, name) {
				a.rrs = append(a.rrs, rr)
			}
		}
	}
	a.nx = resp.Rcode == dns.RcodeNameError && !ownsAny
	return a
}

// ask returns side's answer for (name, qtype).
func (d *zoneDiffer) ask(ctx context.Context, s *zoneSide, name string, qtype uint16) sideAnswer {
	if s.file == nil {
		return d.query(ctx, s.servers, name, qtype)
	}
	if aliases := s.file.aliasFor(name, qtype); len(aliases) > 0 {
		return d.resolveAlias(ctx, s.file, name, qtype, aliases)
	}
	return s.file.answer(name, qtype)
}

// resolveAlias answers (name, qtype) for an ALIAS record in a zone file with
// the addresses its targets resolve to: in-zone targets from the file, other
// targets via the system resolvers (only when a side is a live server).
func (d *zoneDiffer) resolveAlias(ctx context.Context, f *fileZone, name string, qtype uint16, targets []string) sideAnswer {
	a := sideAnswer{alias: targets}
	var unresolved []string
	for _, target := range targets {
		rrs, ok := d.aliasAddrs(ctx, f, target, qtype, 0)
		if !ok {
			unresolved = append(unresolved, target)
			a.extra = append(a.extra, "ALIAS "+target)
			continue
		}
		for _, rr := range rrs {
			c := dns.Copy(rr)
			c.Header().Name = name
			a.rrs = append(a.rrs, c)
		}
	}
	a.note = "ALIAS record — compared resolved addresses of " + strings.Join(targets, ", ")
	if len(unresolved) > 0 {
		a.note = "ALIAS record — target " + strings.Join(unresolved, ", ") + " not resolved"
		if !d.online() {
			a.note += " (offline diff)"
		}
	}
	return a
}

// aliasAddrs returns the qtype records of an ALIAS target; ok is false when
// it cannot be resolved.
func (d *zoneDiffer) aliasAddrs(ctx context.Context, f *fileZone, target string, qtype uint16, depth int) ([]dns.RR, bool) {
	if depth > 5 {
		return nil, false
	}
	if inZone(target, d.zone) && f.exists[target] {
		if next := f.aliasFor(target, qtype); len(next) > 0 {
			var out []dns.RR
			for _, t := range next {
				rrs, ok := d.aliasAddrs(ctx, f, t, qtype, depth+1)
				if !ok {
					return nil, false
				}
				out = append(out, rrs...)
			}
			return out, true
		}
		if rrs := f.rrs[target][qtype]; len(rrs) > 0 {
			return rrs, true
		}
		if cn := f.rrs[target][dns.TypeCNAME]; len(cn) > 0 {
			return d.aliasAddrs(ctx, f, strings.ToLower(cn[0].(*dns.CNAME).Target), qtype, depth+1)
		}
		return nil, true
	}
	if !d.online() {
		return nil, false
	}
	resp, _, err := queryServers(ctx, zoneDiscoveryServers(), target, qtype, d.timeout)
	if err != nil {
		return nil, false
	}
	var out []dns.RR
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out, true
}

// occluded reports whether name lies below a delegation in a zone file
// (glue), where servers answer with a referral instead of the records.
func (d *zoneDiffer) occluded(name string) bool {
	for _, s := range []*zoneSide{d.old, d.new} {
		if s.file != nil && s.file.occluded(name) {
			return true
		}
	}
	return false
}

// diffName compares all relevant types at name. It returns the diffs and
// in-zone names referenced by the records found.
func (d *zoneDiffer) diffName(ctx context.Context, name string) ([]RecordDiff, []string) {
	if d.occluded(name) {
		return nil, nil
	}
	var (
		diffs        []RecordDiff
		more         []string
		oldNX, newNX bool
	)
	for _, t := range d.typesFor(name) {
		if ctx.Err() != nil {
			return nil, nil
		}
		o, n := sideAnswer{nx: true}, sideAnswer{nx: true}
		if !oldNX {
			o = d.ask(ctx, d.old, name, t)
			oldNX = o.nx
		}
		if !newNX {
			n = d.ask(ctx, d.new, name, t)
			newNX = n.nx
		}
		if rd, ok := d.compare(name, t, o, n); ok {
			diffs = append(diffs, rd)
		}
		more = append(more, d.targets(o.rrs)...)
		more = append(more, d.targets(n.rrs)...)
		for _, a := range append(append([]string(nil), o.alias...), n.alias...) {
			if inZone(a, d.zone) {
				more = append(more, a)
			}
		}
		if oldNX && newNX {
			break
		}
	}
	return diffs, more
}

// targets returns in-zone names referenced by CNAME/MX/NS/SRV records.
func (d *zoneDiffer) targets(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		var t string
		switch v := rr.(type) {
		case *dns.CNAME:
			t = v.Target
		case *dns.MX:
			t = v.Mx
		case *dns.NS:
			t = v.Ns
		case *dns.SRV:
			t = v.Target
		default:
			continue
		}
		t = strings.ToLower(t)
		if t != "." && inZone(t, d.zone) {
			out = append(out, t)
		}
	}
	return out
}

func (d *zoneDiffer) compare(name string, qtype uint16, o, n sideAnswer) (RecordDiff, bool) {
	// Resolved ALIAS addresses carry the resolver's TTLs: never compare those.
	withTTL := d.opts.CompareTTL && o.alias == nil && n.alias == nil
	rd := RecordDiff{
		Name: name,
		Type: dns.TypeToString[qtype],
		Old:  d.values(o, withTTL),
		New:  d.values(n, withTTL),
	}
	if rd.Type == "" {
		rd.Type = fmt.Sprintf("TYPE%d", qtype)
	}
	if d.wildcard != "" && name == d.wildcard {
		rd.Name = "*." + d.zone
		rd.Note = "wildcard (probed via a random label)"
	}
	switch {
	case o.err != nil || n.err != nil:
		rd.Status = DiffError
		var parts []string
		if o.err != nil {
			parts = append(parts, "old: "+o.err.Error())
		}
		if n.err != nil {
			parts = append(parts, "new: "+n.err.Error())
		}
		rd.Err = strings.Join(parts, "; ")
	case len(rd.Old) == 0 && len(rd.New) == 0:
		return rd, false
	case len(rd.New) == 0:
		rd.Status = DiffMissing
	case len(rd.Old) == 0:
		rd.Status = DiffExtra
	case equalStrings(rd.Old, rd.New):
		rd.Status = DiffMatch
	default:
		rd.Status = DiffChanged
	}

	var notes []string
	addNote := func(s string) {
		for _, x := range notes {
			if x == s {
				return
			}
		}
		notes = append(notes, s)
	}
	if rd.Note != "" {
		addNote(rd.Note)
	}
	if o.note != "" {
		addNote(o.note)
	}
	if n.note != "" {
		addNote(n.note)
	}
	if qtype == dns.TypeSOA {
		note := "SOA serial ignored"
		if so, sn := soaSerial(o.rrs), soaSerial(n.rrs); so != "" && sn != "" && so != sn {
			note += fmt.Sprintf(" (old %s, new %s)", so, sn)
		}
		if rd.Status == DiffChanged {
			note += "; primary NS/contact usually differ between providers"
			rd.Expected = true
		}
		addNote(note)
	}
	apexNS := qtype == dns.TypeNS && name == d.zone
	if apexNS && rd.Status != DiffMatch && rd.Status != DiffError {
		addNote("apex NS expected to differ when changing provider")
		rd.Expected = rd.Status == DiffChanged
	}
	// Provider exports often leave out the SOA and apex NS, which the
	// provider manages itself.
	if (qtype == dns.TypeSOA || apexNS) && (rd.Status == DiffMissing || rd.Status == DiffExtra) {
		lacking := d.new
		if rd.Status == DiffExtra {
			lacking = d.old
		}
		if lacking.file != nil && len(lacking.file.rrs[d.zone][qtype]) == 0 {
			rd.Expected = true
			addNote(rd.Type + " not in the zone file (managed by the DNS provider)")
		}
	}
	if rd.Status != DiffMatch && rd.Status != DiffError &&
		(cloudflareProxied(d.old, d.new, n, name, qtype) || cloudflareProxied(d.new, d.old, o, name, qtype)) {
		rd.Expected = true
		addNote("proxied by Cloudflare")
	}
	rd.Note = strings.Join(notes, "; ")
	return rd, true
}

// cloudflareProxied reports whether a difference at (name, qtype) between
// the zone file of fileSide and the live answer liveAns of liveSide is
// explained by Cloudflare's proxy: the record is proxied in the file, and the
// live server answers with Cloudflare anycast addresses (A/AAAA) or has
// flattened the CNAME.
func cloudflareProxied(fileSide, liveSide *zoneSide, liveAns sideAnswer, name string, qtype uint16) bool {
	if fileSide.file == nil || liveSide.file != nil || !fileSide.file.proxied[name] || liveAns.nx || liveAns.err != nil {
		return false
	}
	switch qtype {
	case dns.TypeCNAME:
		return len(liveAns.rrs) == 0
	case dns.TypeA, dns.TypeAAAA:
		if len(liveAns.rrs) == 0 {
			return false
		}
		for _, rr := range liveAns.rrs {
			var ip net.IP
			switch v := rr.(type) {
			case *dns.A:
				ip = v.A
			case *dns.AAAA:
				ip = v.AAAA
			}
			if !isCloudflareIP(ip) {
				return false
			}
		}
		return true
	}
	return false
}

// cloudflareNets are Cloudflare's published proxy ranges
// (https://www.cloudflare.com/ips/).
var cloudflareNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	} {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func isCloudflareIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// values renders an answer as sorted, de-duplicated value strings.
func (d *zoneDiffer) values(a sideAnswer, withTTL bool) []string {
	out := normalizeRRs(a.rrs, withTTL)
	if len(a.extra) == 0 {
		return out
	}
	set := map[string]bool{}
	for _, s := range append(out, a.extra...) {
		set[s] = true
	}
	out = out[:0]
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func soaSerial(rrs []dns.RR) string {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return fmt.Sprint(soa.Serial)
		}
	}
	return ""
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizeRRs renders records as sorted, de-duplicated rdata strings.
func normalizeRRs(rrs []dns.RR, withTTL bool) []string {
	set := map[string]bool{}
	for _, rr := range rrs {
		s := rdataString(rr)
		if withTTL {
			s += fmt.Sprintf(" ttl=%d", rr.Header().Ttl)
		}
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func rdataString(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d", strings.ToLower(v.Ns), strings.ToLower(v.Mbox), v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.TXT:
		// Providers split long strings differently; compare the joined value.
		c := *v
		c.Txt = []string{strings.Join(v.Txt, "")}
		rr = &c
	}
	s := strings.TrimPrefix(rr.String(), rr.Header().String())
	switch rr.Header().Rrtype {
	case dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypeSRV, dns.TypePTR, dns.TypeDNAME:
		s = strings.ToLower(s)
	}
	return strings.ReplaceAll(s, "\t", " ")
}

// sortRecordDiffs sorts by name (DNS canonical order: apex first, then by
// labels right to left) and then by type name.
func sortRecordDiffs(r []RecordDiff) {
	sort.SliceStable(r, func(i, j int) bool {
		if c := compareNames(r[i].Name, r[j].Name); c != 0 {
			return c < 0
		}
		return r[i].Type < r[j].Type
	})
}

func compareNames(a, b string) int {
	la, lb := dns.SplitDomainName(a), dns.SplitDomainName(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

// OldSource describes the old side: "zone file <label>" or the servers.
func (r *ZoneDiffResult) OldSource() string {
	if r.OldFile != "" {
		return fileSource(r.OldFile)
	}
	return strings.Join(r.OldServers, ", ")
}

// NewSource describes the new side: "zone file <label>", the discovered
// authoritative servers, or the new server.
func (r *ZoneDiffResult) NewSource() string {
	switch {
	case r.NewFile != "":
		return fileSource(r.NewFile)
	case len(r.NewServers) > 0:
		return strings.Join(r.NewServers, ", ") + " (live authoritative)"
	}
	return r.NewServer
}

func fileSource(label string) string {
	if label == "zone file" {
		return label
	}
	return "zone file " + label
}

// FormatZoneDiff renders r as plain text: a header, a summary line, then one
// block per record that differs (and per matching record if showMatches):
//
//	~ www.example.com. A        changed
//	    - old: 192.0.2.1
//	    + new: 192.0.2.2
//
// Prefixes: "=" match, "~" changed, "-" missing on new, "+" extra on new, "!" error.
func FormatZoneDiff(r *ZoneDiffResult, showMatches bool) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Zone diff for %s\n", r.Domain)
	fmt.Fprintf(&b, "  old: %s\n", r.OldSource())
	fmt.Fprintf(&b, "  new: %s\n", r.NewSource())
	fmt.Fprintf(&b, "  enumeration: %s\n", r.Enumeration)
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "  warning: %s\n", w)
	}
	b.WriteString("\n")
	parts := make([]string, 0, len(AllDiffStatuses))
	for _, s := range AllDiffStatuses {
		parts = append(parts, fmt.Sprintf("%d %s", r.Counts[s], s))
	}
	fmt.Fprintf(&b, "Summary: %s\n", strings.Join(parts, ", "))
	if !r.HasDifferences() {
		b.WriteString("No differences found.\n")
	}

	width := 0
	for _, rd := range r.Records {
		if rd.Status == DiffMatch && !showMatches {
			continue
		}
		if w := len(rd.Name) + 1 + len(rd.Type); w > width {
			width = w
		}
	}
	for _, rd := range r.Records {
		if rd.Status == DiffMatch && !showMatches {
			continue
		}
		b.WriteString("\n")
		label := rd.Name + " " + rd.Type
		fmt.Fprintf(&b, "%s %-*s  %s", statusSymbol(rd.Status), width, label, statusLabel(rd.Status))
		if rd.Expected {
			b.WriteString(" [expected]")
		}
		if rd.Note != "" {
			fmt.Fprintf(&b, " (%s)", rd.Note)
		}
		b.WriteString("\n")
		if rd.Err != "" {
			fmt.Fprintf(&b, "    error: %s\n", rd.Err)
		}
		writeSetDiff(&b, rd.Old, rd.New)
	}
	return b.String()
}

func statusSymbol(s DiffStatus) string {
	switch s {
	case DiffMatch:
		return "="
	case DiffChanged:
		return "~"
	case DiffMissing:
		return "-"
	case DiffExtra:
		return "+"
	default:
		return "!"
	}
}

func statusLabel(s DiffStatus) string {
	switch s {
	case DiffMissing:
		return "missing on new"
	case DiffExtra:
		return "extra on new"
	}
	return s.String()
}

// writeSetDiff prints common values unprefixed, values only on old with
// "- old:" and values only on new with "+ new:".
func writeSetDiff(b *strings.Builder, old, nw []string) {
	inNew := make(map[string]bool, len(nw))
	for _, s := range nw {
		inNew[s] = true
	}
	inOld := make(map[string]bool, len(old))
	for _, s := range old {
		inOld[s] = true
		if inNew[s] {
			fmt.Fprintf(b, "      both: %s\n", s)
		}
	}
	for _, s := range old {
		if !inNew[s] {
			fmt.Fprintf(b, "    - old: %s\n", s)
		}
	}
	for _, s := range nw {
		if !inOld[s] {
			fmt.Fprintf(b, "    + new: %s\n", s)
		}
	}
}

// fileZone is a zone file indexed for answering diff queries.
type fileZone struct {
	zone        string
	rrs         map[string]map[uint16][]dns.RR
	alias       map[string][]fileAlias
	types       map[string]map[uint16]bool // owner name -> types, for enumeration
	exists      map[string]bool            // owner names and empty non-terminals
	delegations map[string]bool            // non-apex names with NS records
	proxied     map[string]bool            // names with a Cloudflare-proxied record
	count       int                        // records used
}

// fileAlias is a provider ALIAS record; types nil means A and AAAA.
type fileAlias struct {
	target string
	types  []uint16
}

// newFileZone indexes z's records inside zone. Records that cannot be parsed
// or lie outside the zone are skipped with a warning.
func newFileZone(z *zonefile.Zone, zone string) (*fileZone, []string, error) {
	if o := strings.ToLower(strings.TrimSpace(z.Origin)); o != "" && o != "." && dns.Fqdn(o) != zone {
		return nil, nil, fmt.Errorf("origin %s does not match the domain %s", dns.Fqdn(o), zone)
	}
	f := &fileZone{
		zone:        zone,
		rrs:         map[string]map[uint16][]dns.RR{},
		alias:       map[string][]fileAlias{},
		types:       map[string]map[uint16]bool{},
		exists:      map[string]bool{zone: true},
		delegations: map[string]bool{},
		proxied:     map[string]bool{},
	}
	var warnings []string
	outside := 0
	addType := func(name string, t uint16) {
		if f.types[name] == nil {
			f.types[name] = map[uint16]bool{}
		}
		f.types[name][t] = true
	}
	for _, r := range z.Records {
		name := strings.ToLower(dns.Fqdn(strings.TrimSpace(r.Name)))
		if !inZone(name, zone) {
			outside++
			continue
		}
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		if typ == zonefile.AliasType || typ == "ANAME" {
			a := fileAlias{target: strings.ToLower(dns.Fqdn(strings.TrimSpace(r.Data)))}
			if i := strings.Index(r.Comment, "alias-type="); i >= 0 {
				v := strings.Fields(r.Comment[i+len("alias-type="):])
				if len(v) > 0 {
					if t, ok := dns.StringToType[strings.ToUpper(v[0])]; ok && (t == dns.TypeA || t == dns.TypeAAAA) {
						a.types = []uint16{t}
					}
				}
			}
			f.alias[name] = append(f.alias[name], a)
			ts := a.types
			if ts == nil {
				ts = []uint16{dns.TypeA, dns.TypeAAAA}
			}
			for _, t := range ts {
				addType(name, t)
			}
		} else {
			r.Name, r.Type = name, typ
			rr, err := r.RR(zone)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skipped %s %s %s: %v", name, typ, r.Data, err))
				continue
			}
			t := rr.Header().Rrtype
			if noiseTypes[t] {
				continue
			}
			if f.rrs[name] == nil {
				f.rrs[name] = map[uint16][]dns.RR{}
			}
			f.rrs[name][t] = append(f.rrs[name][t], rr)
			addType(name, t)
			if t == dns.TypeNS && name != zone {
				f.delegations[name] = true
			}
		}
		if r.Proxied != nil && *r.Proxied {
			f.proxied[name] = true
		}
		f.count++
		for n := name; n != zone && n != "."; n = parentName(n) {
			f.exists[n] = true
		}
	}
	if outside > 0 && f.count == 0 {
		return nil, nil, fmt.Errorf("none of its %d records are inside %s (wrong domain or origin?)", outside, zone)
	}
	if outside > 0 {
		warnings = append(warnings, fmt.Sprintf("ignored %d record(s) outside %s", outside, zone))
	}
	return f, warnings, nil
}

// parentName returns name without its first label ("." for a TLD).
func parentName(name string) string {
	if i := strings.Index(name, "."); i >= 0 && i < len(name)-1 {
		return name[i+1:]
	}
	return "."
}

// occluded reports whether name lies strictly below a delegation.
func (f *fileZone) occluded(name string) bool {
	if !inZone(name, f.zone) {
		return false
	}
	for p := parentName(name); p != f.zone && inZone(p, f.zone); p = parentName(p) {
		if f.delegations[p] {
			return true
		}
	}
	return false
}

// aliasFor returns the ALIAS targets at name that apply to qtype.
func (f *fileZone) aliasFor(name string, qtype uint16) []string {
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil
	}
	var out []string
	for _, a := range f.alias[name] {
		if a.types == nil || containsType(a.types, qtype) {
			out = append(out, a.target)
		}
	}
	return out
}

// answer answers (name, qtype) from the file like an authoritative server
// would, including wildcard synthesis.
func (f *fileZone) answer(name string, qtype uint16) sideAnswer {
	if f.exists[name] {
		return sideAnswer{rrs: f.rrs[name][qtype]}
	}
	for p := parentName(name); inZone(p, f.zone); p = parentName(p) {
		if !f.exists[p] {
			continue
		}
		// p is the closest encloser.
		w := "*." + p
		if !f.exists[w] {
			break
		}
		var out []dns.RR
		for _, rr := range f.rrs[w][qtype] {
			c := dns.Copy(rr)
			c.Header().Name = name
			out = append(out, c)
		}
		return sideAnswer{rrs: out}
	}
	return sideAnswer{nx: true}
}
