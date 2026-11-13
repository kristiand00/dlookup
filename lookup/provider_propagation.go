package lookup

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/miekg/dns"
)

// PublicResolver is a well-known public recursive resolver used by the
// propagation check.
type PublicResolver struct {
	Name     string // e.g. "Cloudflare"
	Location string // operator / location note
	Addr     string // "ip:port"
}

// PropagationResolvers are queried by the propagation check. It is a package
// variable so callers (and tests) can change the list.
var PropagationResolvers = []PublicResolver{
	{"Cloudflare", "Cloudflare, anycast (US)", "1.1.1.1:53"},
	{"Google", "Google, anycast (US)", "8.8.8.8:53"},
	{"Quad9", "Quad9 Foundation, anycast (CH)", "9.9.9.9:53"},
	{"OpenDNS", "Cisco, anycast (US)", "208.67.222.222:53"},
	{"AdGuard", "AdGuard, anycast (CY)", "94.140.14.14:53"},
	{"CleanBrowsing", "CleanBrowsing, anycast (US)", "185.228.168.9:53"},
	{"Control D", "Windscribe, anycast (CA)", "76.76.2.0:53"},
	{"Level3", "Lumen, anycast (US)", "4.2.2.2:53"},
	{"Yandex", "Yandex (RU)", "77.88.8.8:53"},
	{"AliDNS", "Alibaba (CN)", "223.5.5.5:53"},
	{"DNS.SB", "xTom, anycast (DE)", "185.222.222.222:53"},
	{"Comodo", "Comodo Secure DNS (US)", "8.26.56.26:53"},
}

// PropagationProvider compares the answer of public resolvers with the
// domain's authoritative servers.
type PropagationProvider struct{}

func (p *PropagationProvider) Name() string     { return "Propagation" }
func (p *PropagationProvider) FlagName() string { return "propagation" }
func (p *PropagationProvider) Usage() string {
	return "Run Propagation (compare public resolvers with the authoritative answer; type from --qtype, default A) on domains from <filename>"
}
func (p *PropagationProvider) Command() string         { return "" }
func (p *PropagationProvider) CheckAvailability() bool { return true }
func (p *PropagationProvider) ExcludeFromReport() bool { return true }
func (p *PropagationProvider) DomainOnly() bool        { return true }

// propResult is what one resolver (or the authoritative reference) returned.
type propResult struct {
	set   []string // sorted rdata of the records owned by the name
	ttl   uint32
	rcode int
	err   string
}

func (r propResult) answer() string {
	switch {
	case r.err != "":
		return "(" + chkShortErr(r.err) + ")"
	case r.rcode == dns.RcodeNameError:
		return "NXDOMAIN"
	case r.rcode != dns.RcodeSuccess:
		return dns.RcodeToString[r.rcode]
	case len(r.set) == 0:
		return "(no records)"
	}
	return strings.Join(r.set, ", ")
}

// propCollect extracts the records owned by name of type qtype (or a CNAME
// at name) from a response.
func propCollect(a chkAnswer, name string, qtype uint16) propResult {
	if a.msg == nil {
		return propResult{err: a.problem(), rcode: -1}
	}
	res := propResult{rcode: a.msg.Rcode}
	first := true
	for _, rr := range a.msg.Answer {
		h := rr.Header()
		if !strings.EqualFold(h.Name, name) || (h.Rrtype != qtype && h.Rrtype != dns.TypeCNAME) {
			continue
		}
		v := chkRdata(rr)
		if h.Rrtype == dns.TypeCNAME && qtype != dns.TypeCNAME {
			v = "CNAME " + strings.ToLower(v)
		}
		res.set = appendUnique(res.set, v)
		if first || h.Ttl < res.ttl {
			res.ttl = h.Ttl
			first = false
		}
	}
	sort.Strings(res.set)
	return res
}

func (p *PropagationProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, err := chkDomain(target, "propagation")
	if err != nil {
		return "", err
	}
	if err := chkPrepare(opts); err != nil {
		return "", err
	}
	qtype := dns.TypeA
	if opts.QType != "" {
		t, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(opts.QType))]
		if !ok {
			return "", fmt.Errorf("unknown query type %q", opts.QType)
		}
		qtype = t
	}
	typeName := dns.TypeToString[qtype]

	resolvers := append([]PublicResolver(nil), PropagationResolvers...)
	if opts.Server != "" {
		resolvers = append(resolvers, PublicResolver{"--server", "your resolver", serverAddr(opts.Server)})
	}

	// Reference: every authoritative server's answer (they may legitimately
	// rotate subsets, so a resolver matching any of them or a subset of their
	// union counts as current).
	var (
		zone     string
		zoneErr  error
		authRes  []propResult
		authHost []string
	)
	results := make([]propResult, len(resolvers))
	done := make(chan struct{})
	go func() {
		defer close(done)
		chkParallel(ctx, len(resolvers), func(i int) {
			a := chkExchange(ctx, []string{resolvers[i].Addr}, name, qtype, true, false, chkQueryTimeout(opts))
			results[i] = propCollect(a, name, qtype)
		})
	}()
	zone, zoneErr = chkZoneOf(ctx, opts, name)
	if zoneErr == nil {
		hosts, err := chkZoneServers(ctx, opts, zone)
		if err != nil {
			zoneErr = err
		}
		authRes = make([]propResult, len(hosts))
		chkParallel(ctx, len(hosts), func(i int) {
			addrs := hosts[i].queryAddrs()
			if len(addrs) == 0 {
				authRes[i] = propResult{err: hosts[i].Err, rcode: -1}
				return
			}
			authRes[i] = propCollect(chkAtAny(ctx, opts, addrs, name, qtype, false), name, qtype)
		})
		for _, h := range hosts {
			authHost = append(authHost, strings.TrimSuffix(h.Name, "."))
		}
	}
	<-done
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var r chkReport
	r.line("Propagation of %s %s (%d public resolvers)", chkShow(name), typeName, len(resolvers))

	// Build the reference.
	union := map[string]bool{}
	var refs []propResult
	var refTTL uint32
	for _, a := range authRes {
		if a.err != "" || (a.rcode != dns.RcodeSuccess && a.rcode != dns.RcodeNameError) {
			continue
		}
		refs = append(refs, a)
		for _, v := range a.set {
			union[v] = true
		}
		if a.ttl > refTTL {
			refTTL = a.ttl
		}
	}
	r.section("Authoritative (zone %s):", chkShow(zone))
	switch {
	case zoneErr != nil && len(refs) == 0:
		r.bad("no authoritative reference: %v", zoneErr)
	case len(refs) == 0:
		r.bad("none of the authoritative servers (%s) answered", strings.Join(authHost, ", "))
	default:
		distinct := map[string]bool{}
		for _, a := range refs {
			distinct[a.answer()] = true
		}
		rotation := true // same rcode and record count everywhere: typical round robin / GeoDNS
		for _, a := range refs {
			if a.rcode != refs[0].rcode || len(a.set) != len(refs[0].set) {
				rotation = false
			}
		}
		switch {
		case len(distinct) == 1:
			r.ok("%d/%d nameservers agree: %s (TTL %d)", len(refs), len(authRes), refs[0].answer(), refTTL)
		case rotation:
			r.info("nameservers rotate answers (round robin or GeoDNS); any of them counts as current")
			for i, a := range authRes {
				r.detail("%s: %s", authHost[i], a.answer())
			}
		default:
			r.warn("nameservers give different answers (pending update or a stale secondary?)")
			for i, a := range authRes {
				r.detail("%s: %s", authHost[i], a.answer())
			}
		}
		for i, a := range authRes {
			if a.err != "" || (a.rcode != dns.RcodeSuccess && a.rcode != dns.RcodeNameError) {
				r.bad("%s did not answer: %s", authHost[i], a.answer())
			}
		}
	}

	matches := func(res propResult) bool {
		if len(refs) == 0 {
			return false
		}
		for _, a := range refs {
			if a.rcode == res.rcode && strings.Join(a.set, "\n") == strings.Join(res.set, "\n") {
				return true
			}
		}
		if res.rcode != dns.RcodeSuccess || len(res.set) == 0 {
			return false
		}
		for _, v := range res.set {
			if !union[v] {
				return false
			}
		}
		return true
	}

	r.section("Resolvers:")
	var tb strings.Builder
	tw := tabwriter.NewWriter(&tb, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  \tResolver\tOperator / location\tAnswer\tTTL\tStatus")
	var nMatch, nDiff, nErr int
	for i, res := range results {
		rv := resolvers[i]
		ttl := "-"
		if res.err == "" && res.rcode == dns.RcodeSuccess && len(res.set) > 0 {
			ttl = fmt.Sprint(res.ttl)
			if refTTL > 0 {
				ttl = fmt.Sprintf("%d/%d", res.ttl, refTTL)
			}
		}
		mark, status := "✓", "matches authoritative"
		switch {
		case res.err != "" || (res.rcode != dns.RcodeSuccess && res.rcode != dns.RcodeNameError):
			mark, status = "✗", "error"
			nErr++
		case len(refs) == 0:
			mark, status = "!", "no reference"
			nDiff++
		case matches(res):
			nMatch++
		default:
			mark, status = "!", "stale / different"
			nDiff++
		}
		host := strings.TrimSuffix(rv.Addr, ":53")
		fmt.Fprintf(tw, "  %s\t%s (%s)\t%s\t%s\t%s\t%s\n", mark, rv.Name, host, rv.Location, res.answer(), ttl, status)
	}
	tw.Flush()
	r.b.WriteString(tb.String())

	r.oks += nMatch
	r.warns += nDiff
	r.probls += nErr
	r.blank()
	switch {
	case len(refs) == 0:
		r.line("Cannot judge propagation without an authoritative answer.")
	case nDiff == 0 && nErr == 0:
		r.line("All %d resolvers return the authoritative answer.", len(results))
	default:
		r.line("%d of %d resolvers return the authoritative answer; %d differ (cached until their TTL runs out, or GeoDNS/load balancing), %d failed.", nMatch, len(results), nDiff, nErr)
	}
	return r.String(), nil
}

func init() {
	RegisterProvider(&PropagationProvider{})
}
