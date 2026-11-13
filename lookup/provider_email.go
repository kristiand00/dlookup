package lookup

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// EmailProvider checks a domain's mail setup: MX, SPF, DMARC, DKIM,
// MTA-STS, TLS-RPT and BIMI.
type EmailProvider struct{}

func (p *EmailProvider) Name() string     { return "Email" }
func (p *EmailProvider) FlagName() string { return "email" }
func (p *EmailProvider) Usage() string {
	return "Run Email (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI checks) on domains from <filename>"
}
func (p *EmailProvider) Command() string         { return "" }
func (p *EmailProvider) CheckAvailability() bool { return true }
func (p *EmailProvider) DomainOnly() bool        { return true }

// DKIMSelectors are the common selectors probed by the email check.
var DKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail",
	"mandrill", "mxvault", "zoho", "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3",
}

// Test hooks for the MTA-STS policy fetch.
var (
	mtaSTSPolicyURL = func(domain string) string {
		return "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	}
	mtaSTSHTTPClient = &http.Client{
		// RFC 8461 §3.3: redirects must not be followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
)

const (
	spfMaxLookups = 10
	spfMaxVoids   = 2
)

func (p *EmailProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	fq, err := chkDomain(target, "email")
	if err != nil {
		return "", err
	}
	if err := chkPrepare(opts); err != nil {
		return "", err
	}
	domain := strings.TrimSuffix(fq, ".")

	// The independent parts run concurrently, each into its own report.
	var parts [7]chkReport
	var mxHosts []string
	var dmarcPolicy string
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	run(func() { mxHosts = emailCheckMX(ctx, opts, fq, &parts[0]) })
	run(func() { emailCheckSPF(ctx, opts, fq, &parts[1]) })
	run(func() { dmarcPolicy = emailCheckDMARC(ctx, opts, domain, &parts[2]) })
	run(func() { emailCheckDKIM(ctx, opts, domain, &parts[3]) })
	run(func() { emailCheckTLSRPT(ctx, opts, domain, &parts[5]) })
	wg.Wait()
	// MTA-STS compares the policy with the MX hosts; BIMI needs DMARC.
	run(func() { emailCheckMTASTS(ctx, opts, domain, mxHosts, &parts[4]) })
	run(func() { emailCheckBIMI(ctx, opts, domain, dmarcPolicy, &parts[6]) })
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var r chkReport
	r.line("Email checks for %s", domain)
	for i := range parts {
		r.blank()
		r.b.WriteString(parts[i].b.String())
		r.oks += parts[i].oks
		r.warns += parts[i].warns
		r.probls += parts[i].probls
	}
	return r.String(), nil
}

// ---------------------------------------------------------------------------
// MX

// emailCheckMX returns the MX host names (lower case, FQDN).
func emailCheckMX(ctx context.Context, opts Options, fq string, r *chkReport) []string {
	r.line("MX:")
	a := chkRecursive(ctx, opts, fq, dns.TypeMX)
	if a.msg == nil || (a.msg.Rcode != dns.RcodeSuccess && !a.nxdomain()) {
		r.bad("MX lookup failed: %s", a.problem())
		return nil
	}
	if a.nxdomain() {
		r.bad("%s does not exist (NXDOMAIN)", fq)
		return nil
	}
	var mxs []*dns.MX
	for _, rr := range a.records(fq, dns.TypeMX) {
		mxs = append(mxs, rr.(*dns.MX))
	}
	sort.Slice(mxs, func(i, j int) bool {
		if mxs[i].Preference != mxs[j].Preference {
			return mxs[i].Preference < mxs[j].Preference
		}
		return mxs[i].Mx < mxs[j].Mx
	})
	if len(mxs) == 0 {
		addr := chkRecursive(ctx, opts, fq, dns.TypeA)
		if len(addr.records(fq, dns.TypeA)) > 0 {
			r.warn("no MX records: mail falls back to the A record (implicit MX); publish an MX or a null MX (0 .)")
		} else {
			r.info("no MX records and no A record: the domain does not receive mail")
		}
		return nil
	}
	for _, mx := range mxs {
		if mx.Mx == "." {
			if len(mxs) == 1 {
				r.ok("null MX (0 .): the domain explicitly accepts no mail (RFC 7505)")
			} else {
				r.bad("null MX (.) mixed with other MX records (RFC 7505 forbids this)")
			}
			return nil
		}
	}
	var hosts []string
	for _, mx := range mxs {
		hosts = append(hosts, strings.ToLower(mx.Mx))
	}
	resolved := chkResolveHosts(ctx, opts, hosts)
	var bad []string
	for i, mx := range mxs {
		h := resolved[i]
		addrs := strings.Join(h.Addrs, ", ")
		if addrs == "" {
			addrs = "(" + h.Err + ")"
		}
		r.line("  %3d %-32s %s", mx.Preference, hosts[i], addrs)
		if len(h.Addrs) == 0 {
			bad = append(bad, hosts[i])
		}
	}
	switch {
	case len(bad) == len(hosts):
		r.bad("no MX host resolves: %s", strings.Join(bad, ", "))
	case len(bad) > 0:
		r.bad("MX hosts that do not resolve: %s", strings.Join(bad, ", "))
	default:
		r.ok("%d MX record%s, all resolve", len(mxs), plural(len(mxs), "", "s"))
	}
	for i, h := range resolved {
		if h.CNAME != "" {
			r.warn("MX %s is a CNAME to %s (not allowed, RFC 2181 §10.3)", hosts[i], h.CNAME)
		}
		if net.ParseIP(strings.TrimSuffix(hosts[i], ".")) != nil {
			r.bad("MX %s is an IP address, not a host name", hosts[i])
		}
	}
	return hosts
}

// ---------------------------------------------------------------------------
// SPF

// spfTerm is one parsed SPF term.
type spfTerm struct {
	raw       string
	qualifier byte   // '+', '-', '~', '?'
	name      string // mechanism or modifier name, lower case
	arg       string // domain-spec / IP network / modifier value
	modifier  bool
}

var (
	spfModifierRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$`)
	spfMechRe     = regexp.MustCompile(`^([+?~-]?)([A-Za-z][A-Za-z0-9_.-]*)(.*)$`)
	spfCIDRRe     = regexp.MustCompile(`^(/\d{1,2})?(//\d{1,3})?$`)
)

// spfParse parses an SPF record into terms and lists syntax errors.
func spfParse(record string) ([]spfTerm, []string) {
	fields := strings.Fields(record)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return nil, []string{"record does not start with v=spf1"}
	}
	var terms []spfTerm
	var errs []string
	seenMod := map[string]bool{}
	for _, f := range fields[1:] {
		if m := spfModifierRe.FindStringSubmatch(f); m != nil && !strings.ContainsAny(m[1], ":/") {
			name := strings.ToLower(m[1])
			t := spfTerm{raw: f, name: name, arg: m[2], modifier: true}
			if name == "redirect" || name == "exp" {
				if seenMod[name] {
					errs = append(errs, fmt.Sprintf("%q: modifier %s appears more than once", f, name))
				}
				seenMod[name] = true
				if err := spfCheckDomainSpec(m[2]); err != "" {
					errs = append(errs, fmt.Sprintf("%q: %s", f, err))
				}
			}
			terms = append(terms, t)
			continue
		}
		m := spfMechRe.FindStringSubmatch(f)
		if m == nil {
			errs = append(errs, fmt.Sprintf("%q: invalid term", f))
			continue
		}
		t := spfTerm{raw: f, qualifier: '+', name: strings.ToLower(m[2])}
		if m[1] != "" {
			t.qualifier = m[1][0]
		}
		rest := m[3]
		switch t.name {
		case "all":
			if rest != "" {
				errs = append(errs, fmt.Sprintf("%q: 'all' takes no argument", f))
			}
		case "include", "exists":
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				errs = append(errs, fmt.Sprintf("%q: %s needs a domain (%s:<domain>)", f, t.name, t.name))
			} else {
				t.arg = rest[1:]
				if err := spfCheckDomainSpec(t.arg); err != "" {
					errs = append(errs, fmt.Sprintf("%q: %s", f, err))
				}
			}
		case "a", "mx", "ptr":
			spec := rest
			if strings.HasPrefix(spec, ":") {
				spec = spec[1:]
				cidr := ""
				if t.name != "ptr" {
					if i := strings.Index(spec, "/"); i >= 0 {
						spec, cidr = spec[:i], spec[i:]
					}
				}
				t.arg = spec
				if err := spfCheckDomainSpec(spec); err != "" {
					errs = append(errs, fmt.Sprintf("%q: %s", f, err))
				}
				rest = cidr
			}
			if t.name == "ptr" && rest != "" && !strings.HasPrefix(m[3], ":") {
				errs = append(errs, fmt.Sprintf("%q: invalid ptr argument", f))
			} else if t.name != "ptr" && !spfCIDRRe.MatchString(rest) {
				errs = append(errs, fmt.Sprintf("%q: invalid CIDR length", f))
			} else if t.name != "ptr" && rest != "" {
				if !spfCIDROK(rest) {
					errs = append(errs, fmt.Sprintf("%q: CIDR length out of range", f))
				}
			}
		case "ip4", "ip6":
			if !strings.HasPrefix(rest, ":") {
				errs = append(errs, fmt.Sprintf("%q: %s needs an address", f, t.name))
				break
			}
			t.arg = rest[1:]
			if !spfIPOK(t.name, t.arg) {
				errs = append(errs, fmt.Sprintf("%q: invalid %s network", f, t.name))
			}
		default:
			errs = append(errs, fmt.Sprintf("%q: unknown mechanism %q", f, t.name))
		}
		terms = append(terms, t)
	}
	return terms, errs
}

func spfCIDROK(s string) bool {
	parts := strings.SplitN(s, "//", 2)
	if parts[0] != "" {
		n, _ := strconv.Atoi(strings.TrimPrefix(parts[0], "/"))
		if n > 32 {
			return false
		}
	}
	if len(parts) == 2 {
		n, _ := strconv.Atoi(parts[1])
		if n > 128 {
			return false
		}
	}
	return true
}

func spfIPOK(kind, s string) bool {
	ipStr, bits := s, ""
	if i := strings.Index(s, "/"); i >= 0 {
		ipStr, bits = s[:i], s[i+1:]
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	max := 128
	if kind == "ip4" {
		if ip.To4() == nil || strings.Contains(ipStr, ":") {
			return false
		}
		max = 32
	} else if !strings.Contains(ipStr, ":") {
		return false
	}
	if bits != "" {
		n, err := strconv.Atoi(bits)
		if err != nil || n < 0 || n > max {
			return false
		}
	}
	return true
}

func spfHasMacro(s string) bool { return strings.Contains(s, "%") }

func spfCheckDomainSpec(s string) string {
	if s == "" {
		return "empty domain"
	}
	if spfHasMacro(s) {
		return "" // macros are not expanded here
	}
	if _, err := NormalizeTarget(s); err != nil {
		return "invalid domain " + strconv.Quote(s)
	}
	return ""
}

// spfNode is one SPF record in the include/redirect tree.
type spfNode struct {
	via      string // "include:x" / "redirect=x" ("" for the root)
	domain   string
	record   string
	err      string
	lookups  int // DNS-lookup terms in this record and below
	children []*spfNode
}

// spfEval walks an SPF record and everything it includes.
type spfEval struct {
	ctx      context.Context
	opts     Options
	lookups  int
	voids    int
	errs     []string // permerrors
	warns    []string
	ptrUsed  bool
	macros   bool
	queries  int
	visiting map[string]bool
}

const spfMaxQueries = 60 // hard cap on DNS queries per evaluation

func (e *spfEval) query(name string, qtype uint16) chkAnswer {
	e.queries++
	return chkRecursive(e.ctx, e.opts, name, qtype)
}

// fetch returns the domain's single SPF record (or an error description)
// and whether the lookup was void.
func (e *spfEval) fetch(domain string) (record string, problem string, void bool) {
	a := e.query(domain, dns.TypeTXT)
	if a.msg == nil || (a.msg.Rcode != dns.RcodeSuccess && !a.nxdomain()) {
		return "", "TXT lookup failed: " + a.problem(), false
	}
	if a.nxdomain() {
		return "", "domain does not exist (NXDOMAIN)", true
	}
	recs := chkTXTWithPrefix(a.msg.Answer, "v=spf1")
	switch len(recs) {
	case 0:
		return "", "no SPF record", len(a.msg.Answer) == 0
	case 1:
		return recs[0], "", false
	}
	return "", fmt.Sprintf("%d SPF records (must be exactly one)", len(recs)), false
}

func (e *spfEval) walk(n *spfNode, depth int) {
	terms, perrs := spfParse(n.record)
	for _, pe := range perrs {
		if n.via == "" {
			e.errs = append(e.errs, "syntax: "+pe)
		} else {
			e.errs = append(e.errs, fmt.Sprintf("syntax in %s: %s", n.domain, pe))
		}
	}
	hasAll := false
	for _, t := range terms {
		if !t.modifier && t.name == "all" {
			hasAll = true
		}
	}
	start := e.lookups
	for _, t := range terms {
		if e.ctx.Err() != nil {
			return
		}
		name := t.name
		if t.modifier && name != "redirect" {
			continue
		}
		if t.modifier && hasAll {
			continue // redirect is ignored when "all" is present
		}
		target := t.arg
		if target == "" {
			target = n.domain
		}
		switch name {
		case "include", "redirect":
			e.lookups++
			if spfHasMacro(target) {
				e.macros = true
				continue
			}
			target = strings.ToLower(strings.TrimSuffix(target, "."))
			via := "include:" + target
			if name == "redirect" {
				via = "redirect=" + target
			}
			child := &spfNode{via: via, domain: target}
			n.children = append(n.children, child)
			switch {
			case e.visiting[target]:
				child.err = "loop"
				e.errs = append(e.errs, fmt.Sprintf("include loop: %s includes %s again", n.domain, target))
				continue
			case depth >= 10 || e.queries >= spfMaxQueries || e.lookups > 3*spfMaxLookups:
				child.err = "not followed (limit reached)"
				continue
			}
			rec, prob, void := e.fetch(target)
			if void {
				e.voids++
			}
			if prob != "" {
				child.err = prob
				e.errs = append(e.errs, fmt.Sprintf("%s: %s", via, prob))
				continue
			}
			child.record = rec
			e.visiting[target] = true
			e.walk(child, depth+1)
			delete(e.visiting, target)
		case "a", "mx", "exists":
			e.lookups++
			if spfHasMacro(target) {
				e.macros = true
				continue
			}
			if e.queries >= spfMaxQueries {
				continue
			}
			void := false
			switch name {
			case "a":
				a4 := e.query(target, dns.TypeA)
				a6 := e.query(target, dns.TypeAAAA)
				void = len(a4.records("", dns.TypeA)) == 0 && len(a6.records("", dns.TypeAAAA)) == 0 &&
					(a4.nxdomain() || a4.rcode() == dns.RcodeSuccess)
			case "mx":
				a := e.query(target, dns.TypeMX)
				void = len(a.records("", dns.TypeMX)) == 0 && (a.nxdomain() || a.rcode() == dns.RcodeSuccess)
			case "exists":
				a := e.query(target, dns.TypeA)
				void = len(a.records("", dns.TypeA)) == 0 && (a.nxdomain() || a.rcode() == dns.RcodeSuccess)
			}
			if void {
				e.voids++
				e.warns = append(e.warns, fmt.Sprintf("void lookup: %s in %s finds no records", t.raw, n.domain))
			}
		case "ptr":
			e.lookups++
			e.ptrUsed = true
		}
	}
	n.lookups = e.lookups - start
}

func spfPrintTree(r *chkReport, n *spfNode, indent int) {
	for _, c := range n.children {
		pad := strings.Repeat("  ", indent)
		switch {
		case c.err != "":
			r.line("    %s%s (%s)", pad, c.via, c.err)
		default:
			n := c.lookups + 1 // the include/redirect itself counts too
			r.line("    %s%s (%d lookup%s)", pad, c.via, n, plural(n, "", "s"))
		}
		if indent < 4 {
			spfPrintTree(r, c, indent+1)
		}
	}
}

// emailCheckSPF checks the domain's SPF record.
func emailCheckSPF(ctx context.Context, opts Options, fq string, r *chkReport) {
	r.line("SPF:")
	domain := strings.TrimSuffix(fq, ".")
	a := chkRecursive(ctx, opts, fq, dns.TypeTXT)
	if a.msg == nil || (a.msg.Rcode != dns.RcodeSuccess && !a.nxdomain()) {
		r.bad("TXT lookup failed: %s", a.problem())
		return
	}
	recs := chkTXTWithPrefix(a.msg.Answer, "v=spf1")
	switch len(recs) {
	case 0:
		r.warn("no SPF record (v=spf1): anyone can claim to send mail as %s", domain)
		return
	case 1:
	default:
		r.bad("%d SPF records; there must be exactly one (permerror)", len(recs))
		for _, rec := range recs {
			r.detail("%s", rec)
		}
		return
	}
	root := &spfNode{domain: domain, record: recs[0]}
	r.line("  %s", recs[0])
	e := &spfEval{ctx: ctx, opts: opts, visiting: map[string]bool{domain: true}}
	e.walk(root, 0)
	spfPrintTree(r, root, 0)
	spfReport(r, root, e)
}

// spfReport turns an evaluation into verdict lines.
func spfReport(r *chkReport, root *spfNode, e *spfEval) {
	r.ok("exactly one SPF record")
	if len(e.errs) == 0 {
		r.ok("syntax valid, all includes resolve")
	} else {
		for _, msg := range e.errs {
			r.bad("%s", msg)
		}
	}
	more := ""
	if e.macros {
		more = " (macros not expanded)"
	}
	if e.lookups > spfMaxLookups {
		r.bad("%d DNS lookups, over the limit of %d (permerror)%s", e.lookups, spfMaxLookups, more)
	} else if e.lookups >= spfMaxLookups-1 {
		r.warn("%d/%d DNS lookups: at the limit, one more include breaks SPF%s", e.lookups, spfMaxLookups, more)
	} else {
		r.ok("%d/%d DNS lookups%s", e.lookups, spfMaxLookups, more)
	}
	if e.voids > spfMaxVoids {
		r.bad("%d void lookups, over the limit of %d (permerror)", e.voids, spfMaxVoids)
	} else if e.voids > 0 {
		r.warn("%d/%d void lookups", e.voids, spfMaxVoids)
	} else {
		r.ok("0/%d void lookups", spfMaxVoids)
	}
	for _, w := range e.warns {
		r.detail("%s", w)
	}
	if e.ptrUsed {
		r.warn("uses the ptr mechanism (deprecated, RFC 7208 §5.5)")
	}

	terms, _ := spfParse(root.record)
	var all *spfTerm
	redirect := false
	afterAll := []string{}
	for i, t := range terms {
		if all != nil && !t.modifier {
			afterAll = append(afterAll, t.raw)
		}
		if !t.modifier && t.name == "all" && all == nil {
			all = &terms[i]
		}
		if t.modifier && t.name == "redirect" {
			redirect = true
		}
	}
	switch {
	case all == nil && redirect:
		r.ok("policy delegated with redirect=")
	case all == nil:
		r.warn("no 'all' mechanism: unmatched senders get neutral (?all)")
	case all.qualifier == '+':
		r.warn("ends with +all: every server on the internet may send as this domain")
	case all.qualifier == '?':
		r.warn("ends with ?all (neutral): provides no protection")
	case all.qualifier == '~':
		r.ok("ends with ~all (softfail)")
	default:
		r.ok("ends with -all (fail)")
	}
	if len(afterAll) > 0 {
		r.warn("terms after 'all' are ignored: %s", strings.Join(afterAll, " "))
	}
}

// ---------------------------------------------------------------------------
// DMARC

// dmarcRecord is a parsed DMARC record.
type dmarcRecord struct {
	tags map[string]string
	errs []string
}

func dmarcParse(s string) dmarcRecord {
	rec := dmarcRecord{tags: map[string]string{}}
	parts := strings.Split(s, ";")
	first := true
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok || k == "" {
			rec.errs = append(rec.errs, fmt.Sprintf("invalid tag %q", p))
			continue
		}
		if first {
			if k != "v" || v != "DMARC1" {
				rec.errs = append(rec.errs, "record must start with v=DMARC1")
			}
			first = false
		}
		if _, dup := rec.tags[k]; dup {
			rec.errs = append(rec.errs, fmt.Sprintf("tag %s appears more than once", k))
		}
		rec.tags[k] = v
	}
	for _, k := range []string{"p", "sp"} {
		if v, ok := rec.tags[k]; ok {
			switch strings.ToLower(v) {
			case "none", "quarantine", "reject":
				rec.tags[k] = strings.ToLower(v)
			default:
				rec.errs = append(rec.errs, fmt.Sprintf("invalid %s=%s (none, quarantine or reject)", k, v))
			}
		}
	}
	if v, ok := rec.tags["pct"]; ok {
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 100 {
			rec.errs = append(rec.errs, fmt.Sprintf("invalid pct=%s (0-100)", v))
		}
	}
	for _, k := range []string{"adkim", "aspf"} {
		if v, ok := rec.tags[k]; ok && v != "r" && v != "s" {
			rec.errs = append(rec.errs, fmt.Sprintf("invalid %s=%s (r or s)", k, v))
		}
	}
	for _, k := range []string{"rua", "ruf"} {
		if v, ok := rec.tags[k]; ok {
			for _, u := range strings.Split(v, ",") {
				u = strings.TrimSpace(u)
				if !strings.HasPrefix(strings.ToLower(u), "mailto:") || !strings.Contains(u, "@") {
					rec.errs = append(rec.errs, fmt.Sprintf("%s: %q is not a mailto: address", k, u))
				}
			}
		}
	}
	return rec
}

// dmarcReportDomains returns the domains of the rua/ruf mailto addresses.
func dmarcReportDomains(v string) []string {
	var out []string
	for _, u := range strings.Split(v, ",") {
		u = strings.TrimSpace(u)
		if i := strings.LastIndex(u, "@"); i >= 0 {
			d := u[i+1:]
			if j := strings.Index(d, "!"); j >= 0 { // size limit suffix, e.g. "!10m"
				d = d[:j]
			}
			out = appendUnique(out, strings.ToLower(strings.TrimSuffix(d, ".")))
		}
	}
	return out
}

// emailCheckDMARC returns the effective policy ("" when there is none).
func emailCheckDMARC(ctx context.Context, opts Options, domain string, r *chkReport) string {
	r.line("DMARC (_dmarc.%s):", domain)
	a := chkRecursive(ctx, opts, "_dmarc."+domain, dns.TypeTXT)
	if a.msg == nil || (a.msg.Rcode != dns.RcodeSuccess && !a.nxdomain()) {
		r.bad("TXT lookup failed: %s", a.problem())
		return ""
	}
	recs := chkTXTWithPrefix(a.msg.Answer, "v=DMARC1")
	switch len(recs) {
	case 0:
		r.warn("no DMARC record: receivers apply no policy and send no reports")
		return ""
	case 1:
	default:
		r.bad("%d DMARC records; there must be exactly one (DMARC is ignored)", len(recs))
		return ""
	}
	r.line("  %s", recs[0])
	rec := dmarcParse(recs[0])
	for _, e := range rec.errs {
		r.bad("%s", e)
	}
	p, hasP := rec.tags["p"]
	switch {
	case !hasP:
		r.bad("missing p= policy (required)")
	case p == "none":
		r.warn("p=none: monitoring only, spoofed mail is still delivered")
	default:
		r.ok("p=%s", p)
	}
	if sp, ok := rec.tags["sp"]; ok && sp == "none" && p != "none" {
		r.warn("sp=none: subdomains are not protected")
	}
	if v, ok := rec.tags["pct"]; ok && v != "100" {
		r.warn("pct=%s: the policy applies to only %s%% of failing mail", v, v)
	}
	if v, ok := rec.tags["rua"]; ok {
		r.ok("aggregate reports (rua) to %s", v)
		dmarcCheckExternal(ctx, opts, domain, v, r)
	} else {
		r.warn("no rua=: you receive no aggregate reports")
	}
	if v, ok := rec.tags["ruf"]; ok {
		r.info("forensic reports (ruf) to %s", v)
	}
	if !hasP {
		return ""
	}
	return p
}

// dmarcCheckExternal verifies that external report receivers authorise the
// domain (RFC 7489 §7.1).
func dmarcCheckExternal(ctx context.Context, opts Options, domain, rua string, r *chkReport) {
	for _, d := range dmarcReportDomains(rua) {
		if d == domain || strings.HasSuffix(d, "."+domain) || strings.HasSuffix(domain, "."+d) {
			continue
		}
		name := domain + "._report._dmarc." + d
		a := chkRecursive(ctx, opts, name, dns.TypeTXT)
		if a.msg != nil && len(chkTXTWithPrefix(a.msg.Answer, "v=DMARC1")) > 0 {
			continue
		}
		if a.problem() != "" && !a.nxdomain() {
			continue // cannot tell
		}
		r.warn("external report receiver %s has not authorised this domain (%s)", d, name)
	}
}

// ---------------------------------------------------------------------------
// DKIM

// dkimKey describes a published DKIM key.
type dkimKey struct {
	selector string
	keyType  string
	bits     int    // RSA modulus length; 0 when unknown
	revoked  bool   // empty p=
	err      string // unparsable key
	via      string // CNAME target, if any
}

// dkimParse parses a DKIM key record.
func dkimParse(s string) dkimKey {
	k := dkimKey{keyType: "rsa"}
	tags := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		key, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			tags[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(v)
		}
	}
	if v, ok := tags["k"]; ok && v != "" {
		k.keyType = strings.ToLower(v)
	}
	p, ok := tags["p"]
	if !ok {
		k.err = "no p= tag"
		return k
	}
	p = strings.Join(strings.Fields(p), "")
	if p == "" {
		k.revoked = true
		return k
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		k.err = "p= is not valid base64"
		return k
	}
	switch k.keyType {
	case "rsa":
		if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
			if rk, ok := pub.(*rsa.PublicKey); ok {
				k.bits = rk.N.BitLen()
				return k
			}
		}
		if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
			k.bits = rk.N.BitLen()
			return k
		}
		// Fall back to an estimate from the encoded size.
		k.bits = (len(der) - 38) * 8
		if k.bits < 0 {
			k.bits = 0
		}
		k.err = "could not parse the RSA key"
	case "ed25519":
		if len(der) != 32 {
			k.err = fmt.Sprintf("ed25519 key is %d bytes, want 32", len(der))
		}
	}
	return k
}

func emailCheckDKIM(ctx context.Context, opts Options, domain string, r *chkReport) {
	r.line("DKIM (%d common selectors probed):", len(DKIMSelectors))
	selectors := append(append([]string(nil), DKIMSelectors...), "dlookup-wildcard-probe-7f3a")
	type res struct {
		key   dkimKey
		found bool
	}
	results := make([]res, len(selectors))
	chkParallel(ctx, len(selectors), func(i int) {
		name := selectors[i] + "._domainkey." + domain
		a := chkRecursive(ctx, opts, name, dns.TypeTXT)
		if a.msg == nil {
			return
		}
		var via string
		for _, rr := range a.msg.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, dns.Fqdn(name)) {
				via = strings.ToLower(c.Target)
			}
		}
		for _, rr := range a.msg.Answer {
			v, ok := chkTXT(rr)
			if !ok {
				continue
			}
			lv := strings.ToLower(v)
			if !strings.Contains(lv, "p=") && !strings.HasPrefix(lv, "v=dkim1") {
				continue
			}
			k := dkimParse(v)
			k.selector = selectors[i]
			k.via = via
			results[i] = res{key: k, found: true}
			return
		}
	})
	if results[len(results)-1].found {
		r.warn("_domainkey.%s answers for any selector (wildcard): results below are unreliable", domain)
	}
	found := 0
	for _, x := range results[:len(results)-1] {
		if !x.found {
			continue
		}
		found++
		k := x.key
		desc := k.keyType
		if k.via != "" {
			desc += ", via CNAME " + k.via
		}
		switch {
		case k.revoked:
			r.info("%s: key revoked (empty p=)", k.selector)
		case k.err != "":
			r.bad("%s: %s (%s)", k.selector, k.err, desc)
		case k.keyType == "rsa" && k.bits < 1024:
			r.bad("%s: RSA %d bits (too weak, use 2048)%s", k.selector, k.bits, emailVia(k))
		case k.keyType == "rsa" && k.bits < 2048:
			r.warn("%s: RSA %d bits (2048 recommended)%s", k.selector, k.bits, emailVia(k))
		case k.keyType == "rsa":
			r.ok("%s: RSA %d bits%s", k.selector, k.bits, emailVia(k))
		default:
			r.ok("%s: %s%s", k.selector, k.keyType, emailVia(k))
		}
	}
	if found == 0 {
		r.warn("no DKIM key found for common selectors (a custom selector may be in use; check a message's DKIM-Signature s= tag)")
	}
}

func emailVia(k dkimKey) string {
	if k.via == "" {
		return ""
	}
	return " (via " + k.via + ")"
}

// ---------------------------------------------------------------------------
// MTA-STS, TLS-RPT, BIMI

// mtaSTSPolicy is a parsed MTA-STS policy file.
type mtaSTSPolicy struct {
	version string
	mode    string
	maxAge  int
	mx      []string
	errs    []string
}

func mtaSTSParse(body string) mtaSTSPolicy {
	var p mtaSTSPolicy
	p.maxAge = -1
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			p.errs = append(p.errs, fmt.Sprintf("invalid line %q", line))
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "version":
			p.version = v
		case "mode":
			p.mode = strings.ToLower(v)
		case "max_age":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				p.errs = append(p.errs, fmt.Sprintf("invalid max_age %q", v))
			} else {
				p.maxAge = n
			}
		case "mx":
			p.mx = append(p.mx, strings.ToLower(strings.TrimSuffix(v, ".")))
		}
	}
	if p.version != "STSv1" {
		p.errs = append(p.errs, fmt.Sprintf("version is %q, want STSv1", p.version))
	}
	switch p.mode {
	case "enforce", "testing", "none":
	default:
		p.errs = append(p.errs, fmt.Sprintf("invalid mode %q", p.mode))
	}
	if p.maxAge < 0 {
		p.errs = append(p.errs, "missing max_age")
	}
	if len(p.mx) == 0 && p.mode != "none" {
		p.errs = append(p.errs, "no mx: lines")
	}
	return p
}

// matches reports whether the policy's mx patterns cover host.
func (p mtaSTSPolicy) matches(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, m := range p.mx {
		if m == host {
			return true
		}
		if strings.HasPrefix(m, "*.") {
			if i := strings.Index(host, "."); i > 0 && host[i+1:] == m[2:] {
				return true
			}
		}
	}
	return false
}

func mtaSTSFetch(ctx context.Context, opts Options, domain string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mtaSTSPolicyURL(domain), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "dlookup")
	resp, err := mtaSTSHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("HTTP " + resp.Status)
	}
	return string(body), nil
}

func emailCheckMTASTS(ctx context.Context, opts Options, domain string, mxHosts []string, r *chkReport) {
	r.line("MTA-STS (_mta-sts.%s):", domain)
	a := chkRecursive(ctx, opts, "_mta-sts."+domain, dns.TypeTXT)
	var recs []string
	if a.msg != nil {
		recs = chkTXTWithPrefix(a.msg.Answer, "v=STSv1")
	}
	switch {
	case len(recs) == 0 && a.problem() != "" && !a.nxdomain():
		r.bad("TXT lookup failed: %s", a.problem())
		return
	case len(recs) == 0:
		r.info("not configured (optional: protects inbound mail from TLS downgrade)")
		return
	case len(recs) > 1:
		r.bad("%d MTA-STS TXT records (must be exactly one)", len(recs))
		return
	}
	r.line("  %s", recs[0])
	if !strings.Contains(strings.ToLower(recs[0]), "id=") {
		r.bad("TXT record has no id= tag")
	}
	body, err := mtaSTSFetch(ctx, opts, domain)
	if err != nil {
		r.bad("policy %s not retrievable: %v", mtaSTSPolicyURL(domain), err)
		return
	}
	pol := mtaSTSParse(body)
	for _, e := range pol.errs {
		r.bad("policy: %s", e)
	}
	switch pol.mode {
	case "enforce":
		r.ok("policy mode enforce, max_age %d (%s)", pol.maxAge, chkDuration(uint32(max(pol.maxAge, 0))))
	case "testing":
		r.warn("policy mode testing: failures are only reported, not enforced")
	case "none":
		r.warn("policy mode none: MTA-STS is being withdrawn")
	}
	if pol.maxAge >= 0 && pol.maxAge < 86400 && pol.mode != "none" {
		r.warn("max_age %d is short (at least 1 day, ideally weeks, is recommended)", pol.maxAge)
	}
	var uncovered []string
	for _, h := range mxHosts {
		if !pol.matches(h) {
			uncovered = append(uncovered, h)
		}
	}
	switch {
	case pol.mode == "none" || len(mxHosts) == 0:
	case len(uncovered) > 0:
		r.bad("MX hosts not covered by the policy's mx: lines (mail to them fails when enforced): %s", strings.Join(uncovered, ", "))
	default:
		r.ok("policy covers all %d MX host%s", len(mxHosts), plural(len(mxHosts), "", "s"))
	}
}

func emailCheckTLSRPT(ctx context.Context, opts Options, domain string, r *chkReport) {
	r.line("TLS-RPT (_smtp._tls.%s):", domain)
	a := chkRecursive(ctx, opts, "_smtp._tls."+domain, dns.TypeTXT)
	var recs []string
	if a.msg != nil {
		recs = chkTXTWithPrefix(a.msg.Answer, "v=TLSRPTv1")
	}
	switch {
	case len(recs) == 0 && a.problem() != "" && !a.nxdomain():
		r.bad("TXT lookup failed: %s", a.problem())
	case len(recs) == 0:
		r.info("not configured (optional: daily reports about TLS failures delivering to you)")
	case len(recs) > 1:
		r.bad("%d TLS-RPT records (must be exactly one)", len(recs))
	case !strings.Contains(strings.ToLower(recs[0]), "rua="):
		r.bad("TLS-RPT record has no rua=: %s", recs[0])
	default:
		r.ok("%s", recs[0])
	}
}

func emailCheckBIMI(ctx context.Context, opts Options, domain, dmarcPolicy string, r *chkReport) {
	r.line("BIMI (default._bimi.%s):", domain)
	a := chkRecursive(ctx, opts, "default._bimi."+domain, dns.TypeTXT)
	var recs []string
	if a.msg != nil {
		recs = chkTXTWithPrefix(a.msg.Answer, "v=BIMI1")
	}
	switch {
	case len(recs) == 0 && a.problem() != "" && !a.nxdomain():
		r.bad("TXT lookup failed: %s", a.problem())
	case len(recs) == 0:
		r.info("not configured (optional: brand logo in supporting mail clients)")
	case len(recs) > 1:
		r.bad("%d BIMI records (must be exactly one)", len(recs))
	default:
		r.ok("%s", recs[0])
		if dmarcPolicy != "quarantine" && dmarcPolicy != "reject" {
			r.warn("BIMI requires a DMARC policy of quarantine or reject")
		}
		if !strings.Contains(strings.ToLower(recs[0]), "l=") {
			r.warn("BIMI record has no l= logo URL")
		}
	}
}

func init() {
	RegisterProvider(&EmailProvider{})
}
