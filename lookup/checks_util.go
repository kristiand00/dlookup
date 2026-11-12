package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Shared helpers for the DNS health-check providers (propagation, delegation,
// email, takeover, dnssec, ttlplan).
//
// Recursive lookups go to Options.Server (or the system resolvers); queries
// to authoritative servers are sent directly to their IP addresses, port 53,
// with RD clear. Everything here reports DNS failures as data, never as a Go
// error, so the providers can turn them into findings.

// Test hooks.
var (
	// chkDialAddr turns a nameserver IP into the "host:port" queried.
	chkDialAddr = func(ip string) string { return net.JoinHostPort(ip, "53") }
	// chkNow is the clock used for signature expiry and TTL plans.
	chkNow = time.Now
)

// chkConcurrency bounds the number of queries a check runs in parallel.
const chkConcurrency = 8

// DomainOnly may be implemented by providers that only accept domain names.
// The Report skips them for IP targets instead of listing an error.
type DomainOnly interface {
	DomainOnly() bool
}

func domainOnly(p LookupProvider) bool {
	d, ok := p.(DomainOnly)
	return ok && d.DomainOnly()
}

// chkDomain validates target as a domain name (IPs are rejected) and returns
// it fully qualified and lower case.
func chkDomain(target, check string) (string, error) {
	name, err := NormalizeTarget(target)
	if err != nil {
		return "", err
	}
	if net.ParseIP(name) != nil {
		return "", fmt.Errorf("the %s check needs a domain name, not an IP address (%s)", check, name)
	}
	return dns.Fqdn(name), nil
}

// chkPrepare validates opts.Server once up front.
func chkPrepare(opts Options) error {
	if opts.Server != "" {
		return ValidateServer(opts.Server)
	}
	return nil
}

// chkQueryTimeout is the timeout for one query to one server.
func chkQueryTimeout(opts Options) time.Duration {
	t := opts.timeout() / 3
	if t < 2*time.Second {
		t = 2 * time.Second
	}
	if t > 5*time.Second {
		t = 5 * time.Second
	}
	if opts.Timeout > 0 && opts.Timeout < t {
		t = opts.Timeout
	}
	return t
}

// ---------------------------------------------------------------------------
// Report formatting

// chkReport builds the plain-text output: sections, one-line verdicts with
// the markers ✓ (ok), ! (warning) and ✗ (problem), and a summary line.
type chkReport struct {
	b                  strings.Builder
	oks, warns, probls int
}

func (r *chkReport) line(format string, a ...any) {
	r.b.WriteString(strings.TrimRight(fmt.Sprintf(format, a...), " "))
	r.b.WriteString("\n")
}

func (r *chkReport) blank() {
	s := r.b.String()
	if s != "" && !strings.HasSuffix(s, "\n\n") {
		r.b.WriteString("\n")
	}
}

func (r *chkReport) section(format string, a ...any) {
	r.blank()
	r.line(format, a...)
}

func (r *chkReport) ok(format string, a ...any) {
	r.oks++
	r.line("  ✓ "+format, a...)
}

func (r *chkReport) warn(format string, a ...any) {
	r.warns++
	r.line("  ! "+format, a...)
}

func (r *chkReport) bad(format string, a ...any) {
	r.probls++
	r.line("  ✗ "+format, a...)
}

// info is an uncounted note (e.g. an optional feature that is not set up).
func (r *chkReport) info(format string, a ...any) {
	r.line("  - "+format, a...)
}

// detail is an indented line under the previous verdict.
func (r *chkReport) detail(format string, a ...any) {
	r.line("      "+format, a...)
}

func (r *chkReport) summary() string {
	return fmt.Sprintf("%d ok, %d %s, %d %s", r.oks,
		r.warns, plural(r.warns, "warning", "warnings"),
		r.probls, plural(r.probls, "problem", "problems"))
}

func (r *chkReport) String() string {
	return strings.TrimRight(r.b.String(), "\n") + "\n\n" + r.summary()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// chkDuration renders seconds compactly: 300 -> "5m", 86400 -> "1d", 5400 -> "1h30m".
func chkDuration(secs uint32) string {
	if secs == 0 {
		return "0s"
	}
	d := time.Duration(secs) * time.Second
	var parts []string
	if days := d / (24 * time.Hour); days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
		d -= days * 24 * time.Hour
	}
	if h := d / time.Hour; h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
		d -= h * time.Hour
	}
	if m := d / time.Minute; m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
		d -= m * time.Minute
	}
	if s := d / time.Second; s > 0 {
		parts = append(parts, fmt.Sprintf("%ds", s))
	}
	return strings.Join(parts, "")
}

// ---------------------------------------------------------------------------
// Queries

// chkAnswer is the outcome of one query. err is set only when no server
// gave a usable response (network failure, timeout); a response with any
// rcode is returned in msg.
type chkAnswer struct {
	msg    *dns.Msg
	server string
	err    error
}

func (a chkAnswer) rcode() int {
	if a.msg == nil {
		return -1
	}
	return a.msg.Rcode
}

func (a chkAnswer) nxdomain() bool { return a.msg != nil && a.msg.Rcode == dns.RcodeNameError }

// problem describes why the answer is not a NOERROR response, or "".
func (a chkAnswer) problem() string {
	switch {
	case a.err != nil:
		return a.err.Error()
	case a.msg == nil:
		return "no response"
	case a.msg.Rcode != dns.RcodeSuccess:
		return dns.RcodeToString[a.msg.Rcode]
	}
	return ""
}

// records returns the answer records of type qtype owned by name (name ""
// matches any owner).
func (a chkAnswer) records(name string, qtype uint16) []dns.RR {
	if a.msg == nil {
		return nil
	}
	var out []dns.RR
	for _, rr := range a.msg.Answer {
		h := rr.Header()
		if h.Rrtype == qtype && (name == "" || strings.EqualFold(h.Name, name)) {
			out = append(out, rr)
		}
	}
	return out
}

// chkExchange sends name/qtype to each server in turn until one returns a
// response that is not SERVFAIL/REFUSED (those move on to the next server;
// the last such response is returned if nothing better arrives).
func chkExchange(ctx context.Context, servers []string, name string, qtype uint16, rd, do bool, timeout time.Duration) chkAnswer {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = rd
	m.SetEdns0(4096, do)

	var last chkAnswer
	last.err = errors.New("no servers to query")
	for _, s := range servers {
		if err := ctx.Err(); err != nil {
			return chkAnswer{err: err}
		}
		resp, err := exchange(ctx, timeout, m, s)
		if err != nil {
			if last.msg == nil {
				last = chkAnswer{server: s, err: fmt.Errorf("%s: %w", s, err)}
			}
			continue
		}
		last = chkAnswer{msg: resp, server: s}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			continue
		}
		return last
	}
	return last
}

// chkRecursive queries the configured resolver (Options.Server or system).
func chkRecursive(ctx context.Context, opts Options, name string, qtype uint16) chkAnswer {
	return chkExchange(ctx, dnsServers(opts), name, qtype, true, false, chkQueryTimeout(opts))
}

// chkRecursiveDO is chkRecursive with the DNSSEC OK bit set.
func chkRecursiveDO(ctx context.Context, opts Options, name string, qtype uint16) chkAnswer {
	return chkExchange(ctx, dnsServers(opts), name, qtype, true, true, chkQueryTimeout(opts))
}

// chkAt queries one nameserver IP directly (RD clear).
func chkAt(ctx context.Context, opts Options, ip, name string, qtype uint16, do bool) chkAnswer {
	return chkAtAny(ctx, opts, []string{ip}, name, qtype, do)
}

// chkAtAny queries nameserver IPs in turn (RD clear) until one answers.
// The answer's server is the nameserver IP (not the dialled address).
func chkAtAny(ctx context.Context, opts Options, ips []string, name string, qtype uint16, do bool) chkAnswer {
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = chkDialAddr(ip)
	}
	a := chkExchange(ctx, addrs, name, qtype, false, do, chkQueryTimeout(opts))
	for i, addr := range addrs {
		if a.server == addr {
			a.server = ips[i]
			break
		}
	}
	return a
}

// chkParallel runs fn(0..n-1) with at most chkConcurrency in flight.
func chkParallel(ctx context.Context, n int, fn func(i int)) {
	sem := make(chan struct{}, chkConcurrency)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Zones, nameservers and delegations

// chkZoneOf returns the apex of the zone containing name (via SOA through
// the resolver).
func chkZoneOf(ctx context.Context, opts Options, name string) (string, error) {
	name = strings.ToLower(dns.Fqdn(name))
	if name == "." {
		return ".", nil
	}
	orig := name
	for {
		a := chkRecursive(ctx, opts, name, dns.TypeSOA)
		if a.msg == nil {
			return "", fmt.Errorf("finding the zone of %s: %v", orig, a.problem())
		}
		for _, rr := range append(append([]dns.RR(nil), a.msg.Answer...), a.msg.Ns...) {
			if soa, ok := rr.(*dns.SOA); ok && dns.IsSubDomain(soa.Hdr.Name, name) {
				return strings.ToLower(soa.Hdr.Name), nil
			}
		}
		if a.nxdomain() {
			return "", fmt.Errorf("%s does not exist (NXDOMAIN)", name)
		}
		if p := a.problem(); p != "" {
			return "", fmt.Errorf("finding the zone of %s: %s", orig, p)
		}
		// e.g. a CNAME into another zone: the SOA returned belongs to the
		// alias target. Try the parent name.
		labels := dns.SplitDomainName(name)
		if len(labels) <= 1 {
			return "", fmt.Errorf("could not find the zone containing %s (no SOA)", orig)
		}
		name = strings.Join(labels[1:], ".") + "."
	}
}

// chkParentOf returns the apex of the parent zone of zone apex.
func chkParentOf(ctx context.Context, opts Options, apex string) (string, error) {
	if apex == "." {
		return "", errors.New("the root zone has no parent")
	}
	labels := dns.SplitDomainName(apex)
	if len(labels) <= 1 {
		return ".", nil
	}
	return chkZoneOf(ctx, opts, strings.Join(labels[1:], ".")+".")
}

// chkNSHost is a nameserver name with its addresses (IPv4 first).
type chkNSHost struct {
	Name  string
	Addrs []string
	CNAME string // set when the NS name is an alias (not allowed)
	Err   string // resolution problem (NXDOMAIN, SERVFAIL, timeout, no addresses)
	NX    bool
}

func (h chkNSHost) v4() []string {
	var out []string
	for _, a := range h.Addrs {
		if net.ParseIP(a).To4() != nil {
			out = append(out, a)
		}
	}
	return out
}

// queryAddrs returns the addresses to query (IPv4 when there are any, as
// IPv6 connectivity is often missing).
func (h chkNSHost) queryAddrs() []string {
	if v4 := h.v4(); len(v4) > 0 {
		return v4
	}
	return h.Addrs
}

// chkResolveHost looks up A and AAAA for host via the resolver.
func chkResolveHost(ctx context.Context, opts Options, host string) chkNSHost {
	host = strings.ToLower(dns.Fqdn(host))
	out := chkNSHost{Name: host}
	var a4, a6 chkAnswer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a4 = chkRecursive(ctx, opts, host, dns.TypeA) }()
	go func() { defer wg.Done(); a6 = chkRecursive(ctx, opts, host, dns.TypeAAAA) }()
	wg.Wait()
	for _, a := range []chkAnswer{a4, a6} {
		if a.msg == nil {
			continue
		}
		for _, rr := range a.msg.Answer {
			switch v := rr.(type) {
			case *dns.A:
				out.Addrs = appendUnique(out.Addrs, v.A.String())
			case *dns.AAAA:
				out.Addrs = appendUnique(out.Addrs, v.AAAA.String())
			case *dns.CNAME:
				if strings.EqualFold(v.Hdr.Name, host) {
					out.CNAME = strings.ToLower(v.Target)
				}
			}
		}
	}
	out.Addrs = chkSortAddrs(out.Addrs)
	if len(out.Addrs) == 0 {
		switch {
		case a4.nxdomain():
			out.NX = true
			out.Err = "NXDOMAIN"
		case a4.problem() != "":
			out.Err = a4.problem()
		default:
			out.Err = "no A/AAAA records"
		}
	}
	return out
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// chkSortAddrs sorts IPv4 addresses before IPv6, each group sorted.
func chkSortAddrs(addrs []string) []string {
	sort.SliceStable(addrs, func(i, j int) bool {
		a4, b4 := net.ParseIP(addrs[i]).To4() != nil, net.ParseIP(addrs[j]).To4() != nil
		if a4 != b4 {
			return a4
		}
		return addrs[i] < addrs[j]
	})
	return addrs
}

// chkResolveHosts resolves many hosts in parallel, preserving order.
func chkResolveHosts(ctx context.Context, opts Options, hosts []string) []chkNSHost {
	out := make([]chkNSHost, len(hosts))
	chkParallel(ctx, len(hosts), func(i int) { out[i] = chkResolveHost(ctx, opts, hosts[i]) })
	return out
}

// chkNSNames extracts the NS targets owned by owner from rrs, sorted.
func chkNSNames(rrs []dns.RR, owner string) []string {
	var out []string
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, owner) {
			out = appendUnique(out, strings.ToLower(ns.Ns))
		}
	}
	sort.Strings(out)
	return out
}

// chkZoneServers returns the nameservers of zone (NS via the resolver) with
// their addresses.
func chkZoneServers(ctx context.Context, opts Options, zone string) ([]chkNSHost, error) {
	a := chkRecursive(ctx, opts, zone, dns.TypeNS)
	if a.msg == nil {
		return nil, fmt.Errorf("NS lookup for %s: %s", zone, a.problem())
	}
	names := chkNSNames(a.msg.Answer, zone)
	if len(names) == 0 {
		if p := a.problem(); p != "" {
			return nil, fmt.Errorf("NS lookup for %s: %s", zone, p)
		}
		return nil, fmt.Errorf("no NS records for %s", zone)
	}
	return chkResolveHosts(ctx, opts, names), nil
}

// chkAllQueryAddrs returns the query addresses of all hosts, interleaved so
// that consecutive attempts go to different nameservers.
func chkAllQueryAddrs(hosts []chkNSHost) []string {
	var out []string
	for i := 0; ; i++ {
		added := false
		for _, h := range hosts {
			if qa := h.queryAddrs(); i < len(qa) {
				out = append(out, qa[i])
				added = true
			}
		}
		if !added {
			return out
		}
	}
}

// chkReferral is what a parent zone says about a child zone.
type chkReferral struct {
	Zone          string
	Parent        string
	ParentServers []chkNSHost
	NS            []string            // NS names in the referral, sorted
	NSTTL         uint32              // TTL of the NS RRset at the parent
	Glue          map[string][]string // NS name -> glue addresses
	From          string              // server that answered ("ip" or "ip:port")
	Answered      bool                // parent server answered authoritatively (parent and child share servers)
	Msg           *dns.Msg
	Err           error
}

// chkGetReferral asks the parent zone's servers for the delegation of zone.
func chkGetReferral(ctx context.Context, opts Options, zone string) *chkReferral {
	ref := &chkReferral{Zone: zone, Glue: map[string][]string{}}
	parent, err := chkParentOf(ctx, opts, zone)
	if err != nil {
		ref.Err = fmt.Errorf("finding the parent zone: %w", err)
		return ref
	}
	ref.Parent = parent
	servers, err := chkZoneServers(ctx, opts, parent)
	if err != nil {
		ref.Err = fmt.Errorf("finding the parent's nameservers: %w", err)
		return ref
	}
	ref.ParentServers = servers
	addrs := chkAllQueryAddrs(servers)
	if len(addrs) == 0 {
		ref.Err = fmt.Errorf("none of the nameservers of %s resolve", parent)
		return ref
	}
	if len(addrs) > 4 {
		addrs = addrs[:4]
	}
	a := chkAtAny(ctx, opts, addrs, zone, dns.TypeNS, false)
	if a.msg == nil {
		ref.Err = fmt.Errorf("querying the parent's nameservers: %s", a.problem())
		return ref
	}
	ref.Msg = a.msg
	ref.From = a.server
	if a.msg.Rcode != dns.RcodeSuccess {
		ref.Err = fmt.Errorf("parent (%s) answered %s for %s", a.server, dns.RcodeToString[a.msg.Rcode], zone)
		return ref
	}
	section := a.msg.Ns
	if names := chkNSNames(a.msg.Answer, zone); len(names) > 0 {
		section = a.msg.Answer
		ref.Answered = true
	}
	ref.NS = chkNSNames(section, zone)
	for _, rr := range section {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, zone) {
			ref.NSTTL = ns.Hdr.Ttl
			break
		}
	}
	for _, rr := range a.msg.Extra {
		name := strings.ToLower(rr.Header().Name)
		switch v := rr.(type) {
		case *dns.A:
			ref.Glue[name] = appendUnique(ref.Glue[name], v.A.String())
		case *dns.AAAA:
			ref.Glue[name] = appendUnique(ref.Glue[name], v.AAAA.String())
		}
	}
	for k := range ref.Glue {
		ref.Glue[k] = chkSortAddrs(ref.Glue[k])
	}
	if len(ref.NS) == 0 {
		ref.Err = fmt.Errorf("parent (%s) returned no NS records for %s", a.server, zone)
	}
	return ref
}

// chkAuthServers returns the nameservers of zone: from the referral when
// available, otherwise from the resolver's NS answer.
func chkAuthServers(ctx context.Context, opts Options, zone string, ref *chkReferral) []chkNSHost {
	if ref != nil && len(ref.NS) > 0 {
		return chkResolveHosts(ctx, opts, ref.NS)
	}
	hosts, _ := chkZoneServers(ctx, opts, zone)
	return hosts
}

// chkRdata is the record data without owner/TTL/class/type, lower-cased for
// comparison of names.
func chkRdata(rr dns.RR) string {
	s := strings.TrimPrefix(rr.String(), rr.Header().String())
	return strings.TrimSpace(s)
}

// chkTXT joins the character-strings of a TXT record.
func chkTXT(rr dns.RR) (string, bool) {
	t, ok := rr.(*dns.TXT)
	if !ok {
		return "", false
	}
	return strings.Join(t.Txt, ""), true
}

// chkTXTWithPrefix returns the TXT values starting with prefix
// (case-insensitive, followed by end, space or ';').
func chkTXTWithPrefix(rrs []dns.RR, prefix string) []string {
	var out []string
	for _, rr := range filterTXT(rrs, prefix) {
		v, _ := chkTXT(rr)
		out = append(out, strings.TrimSpace(v))
	}
	return out
}

// chkShortErr condenses a network error for table cells.
func chkShortErr(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline exceeded"):
		return "timeout"
	case strings.Contains(l, "connection refused"):
		return "connection refused"
	case strings.Contains(l, "network is unreachable") || strings.Contains(l, "no route to host"):
		return "unreachable"
	}
	return s
}

// chkShow renders a zone name for headers: no trailing dot (except root).
func chkShow(name string) string {
	if name == "." || name == "" {
		return name
	}
	return strings.TrimSuffix(name, ".")
}

// chkServerName labels a queried address with its nameserver name.
func chkServerName(hosts []chkNSHost, server string) string {
	ip := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		ip = h
	}
	for _, h := range hosts {
		for _, a := range h.Addrs {
			if a == ip {
				return chkShow(h.Name) + " (" + ip + ")"
			}
		}
	}
	return ip
}

// chkProbeLabels are common names checked under a domain (copy of the zone
// diff probe list).
var chkProbeLabels = []string{
	"www", "mail", "smtp", "imap", "pop", "webmail", "ftp", "api", "app", "cdn",
	"m", "blog", "shop", "dev", "staging", "vpn", "remote", "autodiscover",
	"autoconfig", "mx", "ns1", "ns2", "_dmarc", "_mta-sts", "mta-sts",
	"_domainkey",
	"_autodiscover._tcp", "_sip._tls", "_sipfederationtls._tcp", "_caldavs._tcp",
	"_carddavs._tcp", "_imaps._tcp", "_submission._tcp", "_xmpp-client._tcp",
}
