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
	Domain      string             `json:"domain"`
	OldServers  []string           `json:"old_servers"` // actually queried
	NewServer   string             `json:"new_server"`  // resolved addr:port
	Enumeration string             `json:"enumeration"` // "axfr from old", "axfr from new", "axfr from old and new" or "probe (N names)"
	Records     []RecordDiff       `json:"records"`     // sorted by name then type
	Counts      map[DiffStatus]int `json:"counts"`
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

type zoneDiffer struct {
	opts       ZoneDiffOptions
	zone       string // FQDN, lowercase
	types      []uint16
	allowFound bool // add types found via AXFR
	timeout    time.Duration
	oldServers []string
	newServer  string
	axfrTypes  map[string]map[uint16]bool // name -> types found in transfer
	wildcard   string                     // random probe name, reported as "*.<zone>"
}

// DiffZone compares the records for opts.Domain served by the old and new servers.
// It returns an error only for invalid options or when a server cannot be
// reached at all; per-record failures are reported as DiffError records.
func DiffZone(ctx context.Context, opts ZoneDiffOptions) (*ZoneDiffResult, error) {
	domain, err := NormalizeTarget(opts.Domain)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(domain) != nil {
		return nil, fmt.Errorf("invalid domain %q: an IP address is not a zone", opts.Domain)
	}
	if strings.TrimSpace(opts.NewServer) == "" {
		return nil, errors.New("new server is required")
	}
	if err := ValidateServer(opts.NewServer); err != nil {
		return nil, err
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
	}
	if d.types == nil {
		d.types = DefaultZoneDiffTypes
	}
	if d.timeout <= 0 {
		d.timeout = DefaultTimeout
	}

	extra := make([]string, 0, len(opts.ExtraNames))
	for _, n := range opts.ExtraNames {
		q, err := qualifyName(n, d.zone)
		if err != nil {
			return nil, err
		}
		extra = append(extra, q)
	}

	if d.newServer, err = resolveServer(ctx, opts.NewServer); err != nil {
		return nil, fmt.Errorf("new server: %w", err)
	}
	if opts.OldServer != "" {
		s, err := resolveServer(ctx, opts.OldServer)
		if err != nil {
			return nil, fmt.Errorf("old server: %w", err)
		}
		d.oldServers = []string{s}
	} else if d.oldServers, err = d.discoverOldServers(ctx); err != nil {
		return nil, err
	}

	// Reachability check; also moves the first working old server to the front.
	used, err := d.checkServer(ctx, d.oldServers)
	if err != nil {
		return nil, fmt.Errorf("old server %s: %w", strings.Join(d.oldServers, ", "), err)
	}
	d.oldServers = moveToFront(d.oldServers, used)
	if _, err := d.checkServer(ctx, []string{d.newServer}); err != nil {
		return nil, fmt.Errorf("new server %s: %w", d.newServer, err)
	}

	res := &ZoneDiffResult{
		Domain:     d.zone,
		OldServers: append([]string(nil), d.oldServers...),
		NewServer:  d.newServer,
		Counts:     map[DiffStatus]int{},
	}

	var names []string
	if opts.TryAXFR {
		var from []string
		d.axfrTypes = map[string]map[uint16]bool{}
		if found, err := axfrTransfer(ctx, d.oldServers, d.zone, d.timeout); err == nil {
			from = append(from, "old")
			mergeTypes(d.axfrTypes, found)
		}
		if found, err := axfrTransfer(ctx, []string{d.newServer}, d.zone, d.timeout); err == nil {
			from = append(from, "new")
			mergeTypes(d.axfrTypes, found)
		}
		if len(from) > 0 {
			res.Enumeration = "axfr from " + strings.Join(from, " and ")
			names = append(names, d.zone)
			for n := range d.axfrTypes {
				names = append(names, n)
			}
			sort.Strings(names)
		} else {
			d.axfrTypes = nil
		}
	}
	if d.axfrTypes == nil {
		names = d.probeNames()
	}
	names = append(names, extra...)

	diffs, total, err := d.run(ctx, names)
	if err != nil {
		return nil, err
	}
	if res.Enumeration == "" {
		res.Enumeration = fmt.Sprintf("probe (%d names)", total)
	}
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

// discoverOldServers finds the authoritative nameservers of the zone
// containing d.zone (walking up via SOA if d.zone itself has no NS) and
// returns their addresses, IPv4 first.
func (d *zoneDiffer) discoverOldServers(ctx context.Context) ([]string, error) {
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
	var lastErr error
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		found, err := axfrOne(ctx, server, zone, timeout)
		if err == nil {
			return found, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func axfrOne(ctx context.Context, server, zone string, timeout time.Duration) (map[string]map[uint16]bool, error) {
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
	found := map[string]map[uint16]bool{}
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
				sawSOA = true
			}
			if noiseTypes[h.Rrtype] || !inZone(name, zone) {
				continue
			}
			if found[name] == nil {
				found[name] = map[uint16]bool{}
			}
			found[name][h.Rrtype] = true
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
	return found, nil
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
	// Types found at this name in a zone transfer are always checked.
	var found []uint16
	for t := range d.axfrTypes[name] {
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

// run checks names (and in-zone names discovered in answers) with a bounded
// worker pool. It returns the diffs and the total number of names checked.
func (d *zoneDiffer) run(ctx context.Context, initial []string) ([]RecordDiff, int, error) {
	workers := d.opts.Concurrency
	if workers <= 0 {
		workers = defaultZoneDiffConcurrent
	}
	seen := map[string]bool{}
	var pending []string
	add := func(n string) {
		if !seen[n] && len(seen) < maxZoneDiffNames {
			seen[n] = true
			pending = append(pending, n)
		}
	}
	for _, n := range initial {
		add(n)
	}

	var (
		mu    sync.Mutex
		diffs []RecordDiff
		done  int
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
					rd, more := d.diffName(ctx, name)
					mu.Lock()
					diffs = append(diffs, rd...)
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
			return nil, 0, err
		}
		mu.Lock()
		sort.Strings(found)
		for _, n := range found {
			add(n)
		}
		mu.Unlock()
	}
	return diffs, len(seen), nil
}

// sideAnswer is one server's answer for (name, type).
type sideAnswer struct {
	rrs []dns.RR // owned by the queried name, of the queried type
	nx  bool     // name does not exist
	err error
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

// diffName compares all relevant types at name. It returns the diffs and
// in-zone names referenced by the records found.
func (d *zoneDiffer) diffName(ctx context.Context, name string) ([]RecordDiff, []string) {
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
			o = d.query(ctx, d.oldServers, name, t)
			oldNX = o.nx
		}
		if !newNX {
			n = d.query(ctx, []string{d.newServer}, name, t)
			newNX = n.nx
		}
		if rd, ok := d.compare(name, t, o, n); ok {
			diffs = append(diffs, rd)
		}
		more = append(more, d.targets(o.rrs)...)
		more = append(more, d.targets(n.rrs)...)
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
	rd := RecordDiff{
		Name: name,
		Type: dns.TypeToString[qtype],
		Old:  d.normalize(o.rrs),
		New:  d.normalize(n.rrs),
	}
	if rd.Type == "" {
		rd.Type = fmt.Sprintf("TYPE%d", qtype)
	}
	if name == d.wildcard {
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
	if rd.Note != "" {
		notes = append(notes, rd.Note)
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
		notes = append(notes, note)
	}
	if qtype == dns.TypeNS && name == d.zone && rd.Status != DiffMatch && rd.Status != DiffError {
		notes = append(notes, "apex NS expected to differ when changing provider")
		rd.Expected = rd.Status == DiffChanged
	}
	rd.Note = strings.Join(notes, "; ")
	return rd, true
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

// normalize renders records as sorted, de-duplicated rdata strings.
func (d *zoneDiffer) normalize(rrs []dns.RR) []string {
	set := map[string]bool{}
	for _, rr := range rrs {
		s := rdataString(rr)
		if d.opts.CompareTTL {
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
	fmt.Fprintf(&b, "  old: %s\n", strings.Join(r.OldServers, ", "))
	fmt.Fprintf(&b, "  new: %s\n", r.NewServer)
	fmt.Fprintf(&b, "  enumeration: %s\n\n", r.Enumeration)
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
