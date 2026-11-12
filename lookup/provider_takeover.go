package lookup

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// TakeoverProvider looks for dangling CNAMEs and NS delegations that could
// allow a subdomain takeover.
type TakeoverProvider struct{}

func (p *TakeoverProvider) Name() string     { return "Takeover" }
func (p *TakeoverProvider) FlagName() string { return "takeover" }
func (p *TakeoverProvider) Usage() string {
	return "Run Takeover (dangling CNAME/NS, subdomain takeover risks on common names) on domains from <filename>"
}
func (p *TakeoverProvider) Command() string         { return "" }
func (p *TakeoverProvider) CheckAvailability() bool { return true }
func (p *TakeoverProvider) ExcludeFromReport() bool { return true }
func (p *TakeoverProvider) DomainOnly() bool        { return true }

// takeoverService is a hosting service whose resources can be claimed by
// anyone once the original owner deletes them while DNS still points there.
type takeoverService struct {
	name string
	re   *regexp.Regexp
}

func tkSvc(name, pattern string) takeoverService {
	return takeoverService{name, regexp.MustCompile(`(?i)` + pattern + `\.?$`)}
}

// takeoverServices are matched against every name in a CNAME chain.
var takeoverServices = []takeoverService{
	tkSvc("AWS S3", `(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com`),
	tkSvc("AWS S3 website", `\.s3-website[.-][a-z0-9-]+\.amazonaws\.com`),
	tkSvc("AWS CloudFront", `\.cloudfront\.net`),
	tkSvc("AWS Elastic Beanstalk", `\.elasticbeanstalk\.com`),
	tkSvc("Azure App Service", `\.azurewebsites\.net`),
	tkSvc("Azure Cloud Services", `\.cloudapp\.(net|azure\.com)`),
	tkSvc("Azure Traffic Manager", `\.trafficmanager\.net`),
	tkSvc("Azure Blob Storage", `\.blob\.core\.windows\.net`),
	tkSvc("Azure CDN", `\.azureedge\.net`),
	tkSvc("Azure Front Door", `\.azurefd\.net`),
	tkSvc("Azure API Management", `\.azure-api\.net`),
	tkSvc("Azure Static Web Apps", `\.azurestaticapps\.net`),
	tkSvc("Heroku", `\.(herokuapp|herokudns|herokussl)\.com`),
	tkSvc("GitHub Pages", `\.github\.io`),
	tkSvc("Ghost", `\.ghost\.io`),
	tkSvc("Shopify", `\.myshopify\.com`),
	tkSvc("Zendesk", `\.zendesk\.com`),
	tkSvc("Fastly", `\.fastly\.net`),
	tkSvc("Netlify", `\.netlify\.(app|com)`),
	tkSvc("Vercel", `(\.vercel-dns\.com|\.vercel\.app|\.now\.sh)`),
	tkSvc("Pantheon", `\.pantheonsite\.io`),
	tkSvc("Read the Docs", `\.readthedocs\.(io|org)`),
	tkSvc("Surge.sh", `\.surge\.sh`),
	tkSvc("Bitbucket", `\.bitbucket\.io`),
	tkSvc("WP Engine", `\.wpengine\.com`),
	tkSvc("Unbounce", `\.unbouncepages\.com`),
	tkSvc("Tumblr", `\.tumblr\.com`),
	tkSvc("WordPress.com", `\.wordpress\.com`),
	tkSvc("Help Scout", `\.helpscoutdocs\.com`),
	tkSvc("HubSpot", `\.(hubspot\.net|hs-sites\.com)`),
	tkSvc("Freshdesk", `\.freshdesk\.com`),
	tkSvc("Intercom", `\.custom\.intercom\.help`),
	tkSvc("Webflow", `\.webflow\.io`),
	tkSvc("Fly.io", `\.fly\.dev`),
	tkSvc("Render", `\.onrender\.com`),
	tkSvc("Google Cloud Storage", `(^|\.)c\.storage\.googleapis\.com`),
	tkSvc("Firebase", `\.(firebaseapp\.com|web\.app)`),
	tkSvc("Strikingly", `\.s\.strikinglydns\.com`),
	tkSvc("Agile CRM", `\.agilecrm\.com`),
	tkSvc("Cargo", `\.cargocollective\.com`),
	tkSvc("Launchrock", `\.launchrock\.com`),
	tkSvc("Tilda", `\.tilda\.ws`),
	tkSvc("Statuspage", `\.statuspage\.io`),
	tkSvc("Uptime Robot", `stats\.uptimerobot\.com`),
	tkSvc("Kinsta", `\.kinsta\.cloud`),
	tkSvc("Teamwork", `\.teamwork\.com`),
	tkSvc("Canny", `\.canny\.io`),
}

// takeoverMatch returns the service a host name belongs to, or "".
func takeoverMatch(host string) string {
	host = strings.ToLower(host)
	for _, s := range takeoverServices {
		if s.re.MatchString(host) {
			return s.name
		}
	}
	return ""
}

// takeoverExtraLabels are names often pointed at third-party services, in
// addition to chkProbeLabels.
var takeoverExtraLabels = []string{
	"store", "docs", "help", "support", "status", "static", "assets", "img",
	"images", "media", "files", "test", "beta", "demo", "portal", "admin",
	"email", "marketing", "go", "info", "news", "landing", "careers", "jobs",
	"events", "community", "forum", "wiki", "kb", "s3", "origin", "download",
	"downloads", "git", "ci", "old", "new", "mobile", "web", "shop", "pages",
	"preview", "uat", "qa", "sandbox", "auth", "login", "sso", "cms", "en",
	"track", "click", "links", "lp", "promo", "partners", "developer", "developers",
}

// takeoverLabels returns the probe labels without SRV-style "_" names.
func takeoverLabels() []string {
	var out []string
	for _, l := range append(append([]string(nil), chkProbeLabels...), takeoverExtraLabels...) {
		if !strings.HasPrefix(l, "_") {
			out = appendUnique(out, l)
		}
	}
	return out
}

// takeoverFinding is the result for one probed name.
type takeoverFinding struct {
	name    string
	chain   []string // CNAME targets in order
	service string
	status  string // "resolves", "NXDOMAIN", "no address", rcode/error
	dangle  bool   // final target does not resolve
	ns      []string
	nsBad   []string // NS hosts that do not exist
	nsFail  string   // delegation broken (SERVFAIL/REFUSED)
	err     string
	ignored bool // wildcard duplicate
}

func takeoverProbe(ctx context.Context, opts Options, name, zone string) takeoverFinding {
	f := takeoverFinding{name: name}
	a := chkRecursive(ctx, opts, name, dns.TypeA)
	if a.msg == nil {
		f.err = a.problem()
		return f
	}
	cur := name
	for i := 0; i < 16; i++ {
		var next string
		for _, rr := range a.msg.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, cur) {
				next = strings.ToLower(c.Target)
			}
		}
		if next == "" {
			break
		}
		f.chain = append(f.chain, next)
		cur = next
	}
	hasAddr := len(a.records("", dns.TypeA)) > 0
	if len(f.chain) > 0 && !hasAddr && a.rcode() == dns.RcodeSuccess {
		// The resolver may have stopped at the chain; check AAAA too.
		a6 := chkRecursive(ctx, opts, name, dns.TypeAAAA)
		hasAddr = len(a6.records("", dns.TypeAAAA)) > 0
	}
	switch {
	case hasAddr:
		f.status = "resolves"
	case a.nxdomain():
		f.status = "NXDOMAIN"
	case a.rcode() == dns.RcodeSuccess:
		f.status = "no address"
	default:
		f.status = a.problem()
	}
	if len(f.chain) > 0 {
		f.dangle = f.status == "NXDOMAIN" || f.status == "no address"
		for _, c := range f.chain {
			if s := takeoverMatch(c); s != "" {
				f.service = s
				break
			}
		}
	}

	// NS delegations (zone apex or delegated subdomains).
	if len(f.chain) == 0 && !a.nxdomain() {
		nsA := chkRecursive(ctx, opts, name, dns.TypeNS)
		f.ns = chkNSNames(nsA.records(name, dns.TypeNS), name)
		if nsA.msg != nil && (nsA.msg.Rcode == dns.RcodeServerFailure || nsA.msg.Rcode == dns.RcodeRefused) && name != zone {
			f.nsFail = dns.RcodeToString[nsA.msg.Rcode]
		}
		for _, h := range f.ns {
			hr := chkResolveHost(ctx, opts, h)
			if hr.NX {
				f.nsBad = append(f.nsBad, h)
			}
		}
	}
	return f
}

func (p *TakeoverProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	fq, err := chkDomain(target, "takeover")
	if err != nil {
		return "", err
	}
	if err := chkPrepare(opts); err != nil {
		return "", err
	}
	names := []string{fq}
	for _, l := range takeoverLabels() {
		names = append(names, l+"."+fq)
	}
	wildcardName := "dlookup-takeover-probe-5c1e." + fq
	names = append(names, wildcardName)

	findings := make([]takeoverFinding, len(names))
	chkParallel(ctx, len(names), func(i int) { findings[i] = takeoverProbe(ctx, opts, names[i], fq) })
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var r chkReport
	r.line("Subdomain takeover check for %s (%d names probed)", strings.TrimSuffix(fq, "."), len(names)-1)

	wild := findings[len(findings)-1]
	findings = findings[:len(findings)-1]
	wildChain := ""
	if len(wild.chain) > 0 {
		wildChain = strings.Join(wild.chain, " ")
		for i := range findings {
			if strings.Join(findings[i].chain, " ") == wildChain {
				findings[i].ignored = true
			}
		}
	}

	r.section("CNAMEs:")
	var cnames []takeoverFinding
	for _, f := range findings {
		if len(f.chain) > 0 && !f.ignored {
			cnames = append(cnames, f)
		}
	}
	if len(cnames) == 0 && wildChain == "" {
		r.line("  (none found)")
	}
	for _, f := range cnames {
		svc := ""
		if f.service != "" {
			svc = " [" + f.service + "]"
		}
		r.line("  %s → %s (%s)%s", strings.TrimSuffix(f.name, "."), strings.Join(f.chain, " → "), f.status, svc)
	}
	if wildChain != "" {
		r.line("  *.%s → %s (%s) — wildcard; names matching it are not listed", strings.TrimSuffix(fq, "."), strings.Join(wild.chain, " → "), wild.status)
		w := wild
		w.name = "*." + fq
		cnames = append(cnames, w)
	}

	var delegated []takeoverFinding
	for _, f := range findings {
		if len(f.ns) > 0 || f.nsFail != "" {
			delegated = append(delegated, f)
		}
	}
	if len(delegated) > 0 {
		r.section("NS delegations:")
		for _, f := range delegated {
			state := strings.Join(f.ns, " ")
			if f.nsFail != "" {
				state = "(" + f.nsFail + ")"
			}
			r.line("  %s NS %s", strings.TrimSuffix(f.name, "."), state)
		}
	}

	r.section("Checks:")
	for _, f := range cnames {
		short := strings.TrimSuffix(f.name, ".")
		final := f.chain[len(f.chain)-1]
		switch {
		case f.dangle && f.service != "":
			r.bad("%s: possible subdomain takeover — %s target %s does not resolve (%s)", short, f.service, final, f.status)
		case f.dangle:
			r.bad("%s: dangling CNAME — %s does not resolve (%s)", short, final, f.status)
		case f.service != "" && f.status == "resolves":
			r.warn("%s: points to %s (%s) — check the resource still exists and is yours", short, f.service, final)
		case f.status != "resolves":
			r.warn("%s: CNAME target %s could not be checked (%s)", short, final, f.status)
		default:
			r.ok("%s: CNAME target %s resolves", short, final)
		}
	}
	for _, f := range delegated {
		short := strings.TrimSuffix(f.name, ".")
		switch {
		case len(f.nsBad) > 0:
			sort.Strings(f.nsBad)
			r.bad("%s: dangling NS delegation — %s do%s not exist (whoever registers them controls %s)",
				short, strings.Join(f.nsBad, ", "), plural(len(f.nsBad), "es", ""), short)
		case f.nsFail != "":
			r.warn("%s: delegated but its nameservers answer %s — if they are on a cloud DNS service, the zone may be claimable", short, f.nsFail)
		default:
			r.ok("%s: all %d nameservers exist", short, len(f.ns))
		}
	}
	var errs []string
	for _, f := range findings {
		if f.err != "" {
			errs = append(errs, fmt.Sprintf("%s (%s)", strings.TrimSuffix(f.name, "."), f.err))
		}
	}
	if len(errs) > 0 {
		r.warn("%d name%s could not be checked: %s", len(errs), plural(len(errs), "", "s"), strings.Join(errs, ", "))
	}
	if len(cnames) == 0 && len(delegated) == 0 && len(errs) == 0 {
		r.ok("no CNAMEs or delegations found among the probed names")
	}
	r.blank()
	r.line("Only common names are probed; names outside the list are not checked.")
	return r.String(), nil
}

func init() {
	RegisterProvider(&TakeoverProvider{})
}
