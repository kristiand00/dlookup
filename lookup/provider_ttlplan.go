package lookup

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// TTLPlanProvider lists the TTLs of a zone's common records and turns them
// into a migration plan: how long to wait after lowering TTLs before
// switching records or providers.
type TTLPlanProvider struct{}

func (p *TTLPlanProvider) Name() string     { return "TTL plan" }
func (p *TTLPlanProvider) FlagName() string { return "ttlplan" }
func (p *TTLPlanProvider) Usage() string {
	return "Run TTL plan (record TTLs and when it is safe to switch after lowering them) on domains from <filename>"
}
func (p *TTLPlanProvider) Command() string         { return "" }
func (p *TTLPlanProvider) CheckAvailability() bool { return true }
func (p *TTLPlanProvider) ExcludeFromReport() bool { return true }
func (p *TTLPlanProvider) DomainOnly() bool        { return true }

// ttlPlanTarget is the TTL records are lowered to before a switch.
const ttlPlanTarget = 300

// ttlRRset is one RRset found while probing.
type ttlRRset struct {
	name  string
	qtype uint16
	ttl   uint32
	count int
	rdata map[string]bool
}

// ttlTypesFor returns the record types probed at name.
func ttlTypesFor(label string) []uint16 {
	switch {
	case label == "":
		return []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeCAA, dns.TypeHTTPS}
	case strings.HasSuffix(label, "._tcp") || strings.HasSuffix(label, "._tls") || strings.HasSuffix(label, "._udp"):
		return []uint16{dns.TypeSRV}
	case strings.HasPrefix(label, "_"):
		return []uint16{dns.TypeTXT}
	}
	return []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT}
}

func (p *TTLPlanProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, err := chkDomain(target, "TTL plan")
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
		r.line("TTL plan for %s", strings.TrimSuffix(name, "."))
		r.section("Checks:")
		r.bad("%v", zerr)
		return r.String(), nil
	}

	var (
		ref   *chkReferral
		hosts []chkNSHost
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() { defer wg.Done(); ref = chkGetReferral(ctx, opts, zone) }()
	hosts, _ = chkZoneServers(ctx, opts, zone)
	wg.Wait()
	addrs := chkAllQueryAddrs(hosts)
	source := "authoritative servers"
	if len(addrs) > 0 {
		// Use one responsive server so TTLs are consistent.
		a := chkAtAny(ctx, opts, addrs, zone, dns.TypeSOA, false)
		if a.msg != nil && a.msg.Rcode == dns.RcodeSuccess && a.msg.Authoritative {
			source = chkServerName(hosts, a.server)
			addrs = append([]string{dnssecHost(a.server)}, addrs...)
		} else {
			addrs = nil
		}
	}
	query := func(qname string, qtype uint16) chkAnswer {
		if len(addrs) > 0 {
			return chkAtAny(ctx, opts, addrs, qname, qtype, false)
		}
		return chkRecursive(ctx, opts, qname, qtype)
	}
	if len(addrs) == 0 {
		source = "resolver (authoritative servers unreachable; TTLs may be partly counted down)"
	}

	type job struct {
		name  string
		qtype uint16
	}
	var jobs []job
	for _, t := range ttlTypesFor("") {
		jobs = append(jobs, job{zone, t})
	}
	labels := append([]string(nil), chkProbeLabels...)
	for _, l := range labels {
		for _, t := range ttlTypesFor(l) {
			jobs = append(jobs, job{l + "." + zone, t})
		}
	}
	answers := make([]chkAnswer, len(jobs))
	chkParallel(ctx, len(jobs), func(i int) { answers[i] = query(jobs[i].name, jobs[i].qtype) })
	if err := ctx.Err(); err != nil {
		return "", err
	}

	sets := map[string]*ttlRRset{}
	var soa *dns.SOA
	for i, a := range answers {
		if a.msg == nil {
			continue
		}
		for _, rr := range a.msg.Answer {
			h := rr.Header()
			if !strings.EqualFold(h.Name, jobs[i].name) || (h.Rrtype != jobs[i].qtype && h.Rrtype != dns.TypeCNAME) {
				continue
			}
			if s, ok := rr.(*dns.SOA); ok {
				soa = s
			}
			key := strings.ToLower(h.Name) + "/" + dns.TypeToString[h.Rrtype]
			set := sets[key]
			if set == nil {
				set = &ttlRRset{name: strings.ToLower(h.Name), qtype: h.Rrtype, ttl: h.Ttl, rdata: map[string]bool{}}
				sets[key] = set
			}
			// A CNAME comes back for every type queried: count records once.
			set.rdata[chkRdata(rr)] = true
			set.count = len(set.rdata)
			if h.Ttl > set.ttl {
				set.ttl = h.Ttl
			}
		}
	}
	list := make([]*ttlRRset, 0, len(sets))
	for _, s := range sets {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].ttl != list[j].ttl {
			return list[i].ttl > list[j].ttl
		}
		if list[i].name != list[j].name {
			return list[i].name < list[j].name
		}
		return list[i].qtype < list[j].qtype
	})

	r.line("TTL plan for %s (TTLs from %s)", chkShow(zone), source)
	if zone != name {
		r.line("%s is inside zone %s; the zone's common names were checked.", chkShow(name), chkShow(zone))
	}
	r.section("Records (%d RRsets, highest TTL first):", len(list))
	if len(list) == 0 {
		r.line("  (none found)")
	} else {
		r.line("  %-8s %-10s %-6s %-36s %s", "TTL", "", "Type", "Name", "Records")
		for _, s := range list {
			r.line("  %-8d %-10s %-6s %-36s %d", s.ttl, chkDuration(s.ttl), dns.TypeToString[s.qtype], s.name, s.count)
		}
	}

	var high []*ttlRRset
	var maxTTL uint32
	for _, s := range list {
		if s.ttl > maxTTL {
			maxTTL = s.ttl
		}
		// The SOA's own TTL hardly matters for a switch.
		if s.ttl > ttlPlanTarget && s.qtype != dns.TypeSOA {
			high = append(high, s)
		}
	}

	r.section("Facts:")
	if len(list) > 0 {
		r.line("  Max TTL:          %d (%s) — %s %s", maxTTL, chkDuration(maxTTL), list[0].name, dns.TypeToString[list[0].qtype])
	}
	if ref.Err == nil && ref.NSTTL > 0 {
		r.line("  Parent NS TTL:    %d (%s) at %s — resolvers may keep using the old nameservers this long after an NS change; only the registry controls it", ref.NSTTL, chkDuration(ref.NSTTL), chkShow(ref.Parent))
	} else if ref.Err != nil {
		r.line("  Parent NS TTL:    unknown (%v)", ref.Err)
	}
	if soa != nil {
		neg := soa.Minttl
		if soa.Hdr.Ttl < neg {
			neg = soa.Hdr.Ttl
		}
		r.line("  Negative TTL:     %d (%s) — how long a \"does not exist\" answer is cached (SOA minimum), relevant for newly added names", neg, chkDuration(neg))
	}

	now := chkNow().UTC()
	r.section("Migration plan:")
	if len(high) == 0 {
		if len(list) > 0 {
			r.line("  All TTLs are already at most %ds: you can switch now; old answers expire from caches within %s.", ttlPlanTarget, chkDuration(maxTTL))
		}
	} else {
		var highMax uint32
		for _, s := range high {
			if s.ttl > highMax {
				highMax = s.ttl
			}
		}
		switchAt := now.Add(time.Duration(highMax) * time.Second)
		r.line("  1. Lower the TTL of these %d RRsets to %d now:", len(high), ttlPlanTarget)
		for _, s := range high {
			r.line("       %-36s %-6s %d → %d", s.name, dns.TypeToString[s.qtype], s.ttl, ttlPlanTarget)
		}
		r.line("  2. Wait at least %s (the highest old TTL) so caches drop the long-lived copies.", chkDuration(highMax))
		r.line("     Earliest safe switch: %s (if TTLs are lowered now).", switchAt.Format("2006-01-02 15:04 UTC"))
		r.line("  3. Switch the records; resolvers pick up the change within %s.", chkDuration(ttlPlanTarget))
		r.line("  4. Raise the TTLs again once the new setup is verified.")
	}
	if ref.Err == nil && ref.NSTTL > 0 {
		r.line("  If you change nameservers: keep the old provider serving the zone for at least %s (parent NS TTL) after the change at the registrar.", chkDuration(ref.NSTTL))
	}

	r.section("Checks:")
	switch {
	case len(list) == 0:
		r.warn("no records found among the probed names")
	case len(high) == 0:
		r.ok("all %d RRsets have TTL ≤ %d: ready to switch", len(list), ttlPlanTarget)
	default:
		r.warn("%d of %d RRsets have TTL > %d: lower them %s before switching", len(high), len(list), ttlPlanTarget, chkDuration(maxTTL))
	}
	return r.String(), nil
}

func init() {
	RegisterProvider(&TTLPlanProvider{})
}
