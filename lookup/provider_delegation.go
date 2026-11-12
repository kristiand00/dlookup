package lookup

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// DelegationProvider checks a zone's delegation from its parent: NS sets,
// lame servers, glue, SOA serials and nameserver diversity.
type DelegationProvider struct{}

func (p *DelegationProvider) Name() string     { return "Delegation" }
func (p *DelegationProvider) FlagName() string { return "delegation" }
func (p *DelegationProvider) Usage() string {
	return "Run Delegation (parent/child NS, lame servers, glue, SOA serials) on domains from <filename>"
}
func (p *DelegationProvider) Command() string         { return "" }
func (p *DelegationProvider) CheckAvailability() bool { return true }
func (p *DelegationProvider) DomainOnly() bool        { return true }

// delegNSResult is what one nameserver address said about the zone.
type delegNSResult struct {
	host      string
	ip        string
	err       string // network error / rcode for the SOA query
	aa        bool
	serial    uint32
	hasSOA    bool
	ns        []string
	nsErr     string
	recursion bool // answered an out-of-zone recursive query
}

// delegRecursionProbe is the out-of-zone name used to detect open recursion.
var delegRecursionProbe = "a.root-servers.net."

func (p *DelegationProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, err := chkDomain(target, "delegation")
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
		r.line("Delegation of %s", strings.TrimSuffix(name, "."))
		r.section("Checks:")
		r.bad("%v", zerr)
		return r.String(), nil
	}
	if zone != name {
		r.line("%s is not a zone apex; checking its zone %s", chkShow(name), chkShow(zone))
	}

	ref := chkGetReferral(ctx, opts, zone)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	parentLabel := ref.Parent
	if parentLabel == "" {
		parentLabel = "?"
	}
	r.line("Delegation of %s (parent zone %s)", chkShow(zone), chkShow(parentLabel))

	// Nameserver names: the parent's view, else the child's (via resolver).
	nsNames := ref.NS
	if len(nsNames) == 0 {
		a := chkRecursive(ctx, opts, zone, dns.TypeNS)
		nsNames = chkNSNames(a.records(zone, dns.TypeNS), zone)
	}
	hosts := chkResolveHosts(ctx, opts, nsNames)

	// Query every address of every nameserver for SOA and NS.
	type job struct{ host, ip string }
	var jobs []job
	for _, h := range hosts {
		addrs := h.Addrs
		if len(addrs) == 0 {
			addrs = ref.Glue[h.Name]
		}
		for _, ip := range addrs {
			if net.ParseIP(ip).To4() == nil && len(h.v4()) > 0 {
				continue // IPv6 is checked only for IPv6-only nameservers
			}
			jobs = append(jobs, job{h.Name, ip})
		}
	}
	results := make([]delegNSResult, len(jobs))
	chkParallel(ctx, len(jobs), func(i int) {
		j := jobs[i]
		res := delegNSResult{host: j.host, ip: j.ip}
		soa := chkAt(ctx, opts, j.ip, zone, dns.TypeSOA, false)
		if soa.msg == nil || soa.msg.Rcode != dns.RcodeSuccess {
			res.err = soa.problem()
		} else {
			res.aa = soa.msg.Authoritative
			for _, rr := range soa.records(zone, dns.TypeSOA) {
				res.serial, res.hasSOA = rr.(*dns.SOA).Serial, true
			}
		}
		if res.err == "" {
			ns := chkAt(ctx, opts, j.ip, zone, dns.TypeNS, false)
			if ns.msg == nil || ns.msg.Rcode != dns.RcodeSuccess {
				res.nsErr = ns.problem()
			} else {
				res.ns = chkNSNames(ns.msg.Answer, zone)
			}
			rec := chkExchange(ctx, []string{chkDialAddr(j.ip)}, delegRecursionProbe, dns.TypeA, true, false, chkQueryTimeout(opts))
			res.recursion = rec.msg != nil && rec.msg.Rcode == dns.RcodeSuccess && rec.msg.RecursionAvailable && len(rec.msg.Answer) > 0
		}
		results[i] = res
	})
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// Parent referral section.
	if ref.Err == nil {
		from := chkServerName(ref.ParentServers, ref.From)
		kind := "referral"
		if ref.Answered {
			kind = "authoritative answer (parent and child share servers)"
		}
		r.section("Parent %s %s from %s, NS TTL %d (%s):", chkShow(ref.Parent), kind, from, ref.NSTTL, chkDuration(ref.NSTTL))
		for _, ns := range ref.NS {
			if g := ref.Glue[ns]; len(g) > 0 {
				r.line("  %-30s glue %s", ns, strings.Join(g, ", "))
			} else {
				r.line("  %s", ns)
			}
		}
	}

	r.section("Nameservers:")
	for _, res := range results {
		state := ""
		switch {
		case res.err != "":
			state = "error: " + res.err
		case !res.aa:
			state = "NOT authoritative (lame)"
		default:
			state = "authoritative"
			if res.hasSOA {
				state += fmt.Sprintf(", serial %d", res.serial)
			}
		}
		r.line("  %-30s %-16s %s", res.host, res.ip, state)
	}
	for _, h := range hosts {
		if len(h.Addrs) == 0 && len(ref.Glue[h.Name]) == 0 {
			r.line("  %-30s %-16s does not resolve: %s", h.Name, "-", h.Err)
		}
	}

	r.section("Checks:")
	if ref.Err != nil {
		r.bad("no delegation from the parent: %v", ref.Err)
	} else {
		r.ok("parent %s delegates %s to %d nameserver%s", chkShow(ref.Parent), chkShow(zone), len(ref.NS), plural(len(ref.NS), "", "s"))
	}

	// Count.
	switch n := len(nsNames); {
	case n == 0:
		r.bad("no nameservers found")
	case n == 1:
		r.bad("only 1 nameserver (at least 2 are required, RFC 1034)")
	default:
		r.ok("%d nameservers (at least 2 required)", n)
	}

	// Resolution and CNAMEs.
	var unresolved, cnamed []string
	for _, h := range hosts {
		if len(h.Addrs) == 0 {
			unresolved = append(unresolved, fmt.Sprintf("%s (%s)", h.Name, h.Err))
		}
		if h.CNAME != "" {
			cnamed = append(cnamed, h.Name+" → "+h.CNAME)
		}
	}
	if len(hosts) > 0 {
		if len(unresolved) == 0 {
			r.ok("all nameserver names resolve")
		} else {
			r.bad("nameserver names do not resolve: %s", strings.Join(unresolved, ", "))
		}
		if len(cnamed) == 0 {
			r.ok("no nameserver name is a CNAME")
		} else {
			r.bad("nameserver names are CNAMEs (not allowed, RFC 2181 §10.3): %s", strings.Join(cnamed, ", "))
		}
	}

	// Lame delegation.
	var lame, failed []string
	answered := 0
	for _, res := range results {
		switch {
		case res.err != "":
			failed = append(failed, fmt.Sprintf("%s %s (%s)", res.host, res.ip, res.err))
		case !res.aa:
			lame = append(lame, fmt.Sprintf("%s %s", res.host, res.ip))
		default:
			answered++
		}
	}
	if len(results) > 0 {
		if len(lame) == 0 && len(failed) == 0 {
			r.ok("all %d nameserver addresses answer authoritatively", len(results))
		}
		if len(lame) > 0 {
			r.bad("lame delegation: not authoritative for %s: %s", chkShow(zone), strings.Join(lame, ", "))
		}
		if len(failed) > 0 {
			r.bad("nameservers not answering: %s", strings.Join(failed, ", "))
		}
	}

	// Parent vs child NS sets.
	if ref.Err == nil && answered > 0 {
		parentSet := strings.Join(ref.NS, " ")
		var diffs []string
		childSets := map[string]bool{}
		for _, res := range results {
			if res.err != "" || !res.aa || res.nsErr != "" {
				continue
			}
			set := strings.Join(res.ns, " ")
			childSets[set] = true
			if set != parentSet {
				diffs = append(diffs, fmt.Sprintf("%s: %s", res.host, delegSetDiff(ref.NS, res.ns)))
			}
		}
		switch {
		case len(childSets) == 0:
		case len(diffs) == 0:
			r.ok("parent and child NS sets match")
		default:
			r.warn("parent and child NS sets differ")
			sort.Strings(diffs)
			for _, d := range delegUnique(diffs) {
				r.detail("%s", d)
			}
		}
		if len(childSets) > 1 {
			r.warn("nameservers disagree about the NS set (%d different sets)", len(childSets))
		}
	}

	// SOA serials.
	serials := map[uint32][]string{}
	for _, res := range results {
		if res.hasSOA && res.aa {
			serials[res.serial] = append(serials[res.serial], res.host)
		}
	}
	switch {
	case len(serials) == 1:
		for s := range serials {
			r.ok("SOA serial %d on all nameservers", s)
		}
	case len(serials) > 1:
		r.warn("SOA serials differ (zone transfer lagging or broken?)")
		keys := make([]uint32, 0, len(serials))
		for s := range serials {
			keys = append(keys, s)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })
		for _, s := range keys {
			r.detail("%d: %s", s, strings.Join(delegUnique(serials[s]), ", "))
		}
	}

	// Glue.
	if ref.Err == nil {
		delegCheckGlue(ctx, opts, &r, zone, ref, hosts, results)
	}

	// Network diversity.
	nets := map[string]bool{}
	var v4count int
	for _, h := range hosts {
		for _, ip := range h.v4() {
			v4count++
			p := net.ParseIP(ip).To4()
			nets[fmt.Sprintf("%d.%d.%d.0/24", p[0], p[1], p[2])] = true
		}
	}
	switch {
	case v4count < 2:
	case len(nets) == 1:
		var only string
		for n := range nets {
			only = n
		}
		r.warn("all IPv4 nameserver addresses are in one /24 network (%s): no network diversity", only)
	default:
		r.ok("nameservers spread over %d /24 networks", len(nets))
	}

	// Open recursion.
	var open []string
	for _, res := range results {
		if res.recursion {
			open = append(open, fmt.Sprintf("%s %s", res.host, res.ip))
		}
	}
	if len(open) > 0 {
		r.warn("authoritative servers also answer recursive queries (open resolver, abuse risk): %s", strings.Join(open, ", "))
	} else if answered > 0 {
		r.ok("no open recursion on the authoritative servers")
	}

	return r.String(), nil
}

// delegCheckGlue checks glue for in-bailiwick nameservers against the
// addresses the zone itself publishes.
func delegCheckGlue(ctx context.Context, opts Options, r *chkReport, zone string, ref *chkReferral, hosts []chkNSHost, results []delegNSResult) {
	var authIPs []string
	for _, res := range results {
		if res.err == "" && res.aa {
			authIPs = append(authIPs, res.ip)
		}
	}
	var inBailiwick []string
	for _, ns := range ref.NS {
		if dns.IsSubDomain(zone, ns) {
			inBailiwick = append(inBailiwick, ns)
		}
	}
	if len(inBailiwick) == 0 {
		r.ok("no glue needed (all nameservers are outside %s)", chkShow(zone))
		return
	}
	resolved := map[string][]string{}
	for _, h := range hosts {
		resolved[h.Name] = h.Addrs
	}
	allOK := true
	for _, ns := range inBailiwick {
		glue := ref.Glue[ns]
		if len(glue) == 0 {
			allOK = false
			r.bad("missing glue for in-bailiwick nameserver %s", ns)
			continue
		}
		// Prefer the zone's own A/AAAA (authoritative), else the resolver's.
		var child []string
		if len(authIPs) > 0 {
			for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
				a := chkAtAny(ctx, opts, authIPs, ns, t, false)
				for _, rr := range a.records(ns, t) {
					switch v := rr.(type) {
					case *dns.A:
						child = append(child, v.A.String())
					case *dns.AAAA:
						child = append(child, v.AAAA.String())
					}
				}
			}
		} else {
			child = resolved[ns]
		}
		child = chkSortAddrs(child)
		if len(child) > 0 && strings.Join(child, ",") != strings.Join(glue, ",") {
			allOK = false
			r.bad("glue for %s (%s) does not match the zone (%s)", ns, strings.Join(glue, ", "), strings.Join(child, ", "))
		}
	}
	if allOK {
		r.ok("glue present and matching for %d in-bailiwick nameserver%s", len(inBailiwick), plural(len(inBailiwick), "", "s"))
	}
}

func delegSetDiff(parent, child []string) string {
	in := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	var parts []string
	for _, p := range parent {
		if !in(child, p) {
			parts = append(parts, "missing "+p)
		}
	}
	for _, c := range child {
		if !in(parent, c) {
			parts = append(parts, "extra "+c)
		}
	}
	if len(child) == 0 {
		return "no NS records"
	}
	return strings.Join(parts, ", ")
}

func delegUnique(list []string) []string {
	var out []string
	for _, s := range list {
		out = appendUnique(out, s)
	}
	return out
}

func init() {
	RegisterProvider(&DelegationProvider{})
}
