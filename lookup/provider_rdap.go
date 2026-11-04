package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// RDAP (RFC 9082/9083) is the structured, HTTPS-based successor of WHOIS.
// The RDAP server for a TLD or IP range is found through the IANA bootstrap
// registries (RFC 9224), which are fetched on demand and cached in memory.

// RDAPBootstrapBaseURL is the base URL of the IANA bootstrap files
// (dns.json, ipv4.json, ipv6.json). Tests may point it at a local server.
var RDAPBootstrapBaseURL = "https://data.iana.org/rdap/"

// RDAPHTTPClient performs all RDAP requests. Timeouts come from the request
// context (Options.Timeout), so the client itself has none.
var RDAPHTTPClient = &http.Client{}

// rdapBootstrapTTL is how long a fetched bootstrap file is reused.
const rdapBootstrapTTL = 24 * time.Hour

// maxRDAPBody bounds how much of a response we read.
const maxRDAPBody = 8 << 20

type rdapService struct {
	keys []string // TLDs or CIDR prefixes
	urls []string
}

type rdapBootstrap struct {
	services []rdapService
	fetched  time.Time
}

var (
	rdapCacheMu sync.Mutex
	rdapCache   = map[string]*rdapBootstrap{} // keyed by full bootstrap URL
)

type RDAPProvider struct{}

func (p *RDAPProvider) Name() string     { return "RDAP" }
func (p *RDAPProvider) FlagName() string { return "rdap" }
func (p *RDAPProvider) Usage() string {
	return fmt.Sprintf("Run %s (registration data over HTTPS) lookup on domains from <filename>", p.Name())
}
func (p *RDAPProvider) Command() string         { return "" }
func (p *RDAPProvider) CheckAvailability() bool { return true }

// Execute queries RDAP for a domain or IP address. opts.Server (a DNS server) is ignored.
func (p *RDAPProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	name, err := normalizeTarget(target)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	if ip := net.ParseIP(name); ip != nil {
		file := "ipv6.json"
		if ip.To4() != nil {
			file = "ipv4.json"
		}
		bs, err := fetchBootstrap(ctx, file)
		if err != nil {
			return "", err
		}
		base, ok := bs.lookupIP(ip)
		if !ok {
			return "", fmt.Errorf("no RDAP service known for %s", name)
		}
		obj, src, err := fetchRDAP(ctx, base, "ip/"+ip.String())
		if err != nil {
			return "", err
		}
		return formatRDAPIP(obj, src), nil
	}

	bs, err := fetchBootstrap(ctx, "dns.json")
	if err != nil {
		return "", err
	}
	base, ok := bs.lookupDomain(name)
	if !ok {
		return "", fmt.Errorf("no RDAP service known for the TLD of %s", name)
	}
	// Without a public-suffix list we don't know where the registered domain
	// starts, so strip leading labels on 404 (www.example.co.uk -> example.co.uk).
	labels := strings.Split(name, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		obj, src, err := fetchRDAP(ctx, base, "domain/"+candidate)
		if errors.Is(err, errRDAPNotFound) && i < len(labels)-2 {
			continue
		}
		if err != nil {
			return "", err
		}
		return formatRDAPDomain(obj, src), nil
	}
	return "", fmt.Errorf("%s: %w", name, errRDAPNotFound)
}

var errRDAPNotFound = errors.New("not found in RDAP")

func fetchBootstrap(ctx context.Context, file string) (*rdapBootstrap, error) {
	u := strings.TrimSuffix(RDAPBootstrapBaseURL, "/") + "/" + file

	rdapCacheMu.Lock()
	defer rdapCacheMu.Unlock()
	if bs, ok := rdapCache[u]; ok && time.Since(bs.fetched) < rdapBootstrapTTL {
		return bs, nil
	}

	body, _, err := httpGetJSON(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("fetching RDAP bootstrap %s: %w", u, err)
	}
	bs, err := parseBootstrap(body)
	if err != nil {
		return nil, fmt.Errorf("parsing RDAP bootstrap %s: %w", u, err)
	}
	rdapCache[u] = bs
	return bs, nil
}

func parseBootstrap(body []byte) (*rdapBootstrap, error) {
	var raw struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	bs := &rdapBootstrap{fetched: time.Now()}
	for _, svc := range raw.Services {
		if len(svc) < 2 {
			continue
		}
		bs.services = append(bs.services, rdapService{keys: svc[0], urls: svc[1]})
	}
	if len(bs.services) == 0 {
		return nil, errors.New("no services listed")
	}
	return bs, nil
}

// lookupDomain returns the RDAP base URL for the longest matching suffix of name.
func (bs *rdapBootstrap) lookupDomain(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	best, bestLen := "", -1
	for _, svc := range bs.services {
		for _, k := range svc.keys {
			k = strings.ToLower(strings.Trim(k, "."))
			if (name == k || strings.HasSuffix(name, "."+k)) && len(k) > bestLen {
				if u := pickURL(svc.urls); u != "" {
					best, bestLen = u, len(k)
				}
			}
		}
	}
	return best, bestLen >= 0
}

// lookupIP returns the RDAP base URL for the most specific prefix containing ip.
func (bs *rdapBootstrap) lookupIP(ip net.IP) (string, bool) {
	best, bestBits := "", -1
	for _, svc := range bs.services {
		for _, k := range svc.keys {
			_, n, err := net.ParseCIDR(k)
			if err != nil || !n.Contains(ip) {
				continue
			}
			if ones, _ := n.Mask.Size(); ones > bestBits {
				if u := pickURL(svc.urls); u != "" {
					best, bestBits = u, ones
				}
			}
		}
	}
	return best, bestBits >= 0
}

// pickURL prefers an https base URL.
func pickURL(urls []string) string {
	for _, u := range urls {
		if strings.HasPrefix(strings.ToLower(u), "https://") {
			return u
		}
	}
	if len(urls) > 0 {
		return urls[0]
	}
	return ""
}

func httpGetJSON(ctx context.Context, u string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "dlookup")
	resp, err := RDAPHTTPClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, ctxErr
		}
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRDAPBody))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return body, resp.StatusCode, errRDAPNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := resp.Status
		var e rdapObject
		if json.Unmarshal(body, &e) == nil && e.Title != "" {
			msg += ": " + e.Title
		}
		return body, resp.StatusCode, fmt.Errorf("HTTP %s", msg)
	}
	return body, resp.StatusCode, nil
}

func fetchRDAP(ctx context.Context, base, path string) (*rdapObject, string, error) {
	if _, err := url.Parse(base); err != nil {
		return nil, "", fmt.Errorf("bad RDAP base URL %q: %w", base, err)
	}
	u := strings.TrimSuffix(base, "/") + "/" + path
	body, _, err := httpGetJSON(ctx, u)
	if err != nil {
		return nil, u, err
	}
	obj, err := parseRDAP(body)
	if err != nil {
		return nil, u, fmt.Errorf("parsing RDAP response from %s: %w", u, err)
	}
	return obj, u, nil
}

// --- Response model (subset of RFC 9083) ---

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

type rdapObject struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	LDHName         string       `json:"ldhName"`
	UnicodeName     string       `json:"unicodeName"`
	Status          []string     `json:"status"`
	Events          []rdapEvent  `json:"events"`
	Entities        []rdapEntity `json:"entities"`
	Nameservers     []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned *bool `json:"delegationSigned"`
	} `json:"secureDNS"`

	// IP network fields
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	IPVersion    string `json:"ipVersion"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	Cidrs        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`

	// Error fields
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

func parseRDAP(body []byte) (*rdapObject, error) {
	var obj rdapObject
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

// vcardField returns the first value of a jCard (RFC 7095) property, e.g. "fn".
func vcardField(raw json.RawMessage, field string) string {
	if len(raw) == 0 {
		return ""
	}
	var card []json.RawMessage
	if json.Unmarshal(raw, &card) != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(card[1], &props) != nil {
		return ""
	}
	for _, prop := range props {
		if len(prop) < 4 {
			continue
		}
		var name string
		if json.Unmarshal(prop[0], &name) != nil || !strings.EqualFold(name, field) {
			continue
		}
		var s string
		if json.Unmarshal(prop[3], &s) == nil {
			return strings.TrimSpace(s)
		}
		var parts []string // structured values, e.g. "adr" or "n"
		if json.Unmarshal(prop[3], &parts) == nil {
			return strings.TrimSpace(strings.Join(nonEmpty(parts), ", "))
		}
	}
	return ""
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// findEntity searches entities (recursively) for the first one with role.
func findEntity(ents []rdapEntity, role string) *rdapEntity {
	for i := range ents {
		for _, r := range ents[i].Roles {
			if strings.EqualFold(r, role) {
				return &ents[i]
			}
		}
	}
	for i := range ents {
		if e := findEntity(ents[i].Entities, role); e != nil {
			return e
		}
	}
	return nil
}

func entityName(e *rdapEntity) string {
	if e == nil {
		return ""
	}
	if n := vcardField(e.VCardArray, "fn"); n != "" {
		return n
	}
	if n := vcardField(e.VCardArray, "org"); n != "" {
		return n
	}
	return e.Handle
}

func eventDate(evs []rdapEvent, action string) string {
	for _, ev := range evs {
		if strings.EqualFold(ev.Action, action) {
			return formatRDAPDate(ev.Date)
		}
	}
	return ""
}

func formatRDAPDate(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

type kvWriter struct {
	b strings.Builder
}

func (w *kvWriter) add(key, val string) {
	if val == "" {
		return
	}
	fmt.Fprintf(&w.b, "%-13s %s\n", key+":", val)
}

func (w *kvWriter) String() string { return strings.TrimRight(w.b.String(), "\n") }

func formatRDAPDomain(o *rdapObject, source string) string {
	var w kvWriter
	name := o.LDHName
	if o.UnicodeName != "" && !strings.EqualFold(o.UnicodeName, o.LDHName) {
		name = fmt.Sprintf("%s (%s)", o.UnicodeName, o.LDHName)
	}
	w.add("Domain", name)

	if reg := findEntity(o.Entities, "registrar"); reg != nil {
		r := entityName(reg)
		for _, id := range reg.PublicIDs {
			if strings.Contains(strings.ToLower(id.Type), "iana") && id.Identifier != "" {
				r += fmt.Sprintf(" (IANA ID %s)", id.Identifier)
				break
			}
		}
		w.add("Registrar", r)
	}
	w.add("Registrant", entityName(findEntity(o.Entities, "registrant")))
	w.add("Status", strings.Join(o.Status, ", "))
	w.add("Created", eventDate(o.Events, "registration"))
	w.add("Expires", eventDate(o.Events, "expiration"))
	w.add("Updated", eventDate(o.Events, "last changed"))

	ns := make([]string, 0, len(o.Nameservers))
	for _, n := range o.Nameservers {
		if n.LDHName != "" {
			ns = append(ns, strings.ToLower(n.LDHName))
		}
	}
	sort.Strings(ns)
	w.add("Nameservers", strings.Join(ns, ", "))

	if o.SecureDNS != nil && o.SecureDNS.DelegationSigned != nil {
		if *o.SecureDNS.DelegationSigned {
			w.add("DNSSEC", "signed")
		} else {
			w.add("DNSSEC", "unsigned")
		}
	}
	if abuse := findEntity(o.Entities, "abuse"); abuse != nil {
		w.add("Abuse", vcardField(abuse.VCardArray, "email"))
	}
	w.add("Source", source)
	return w.String()
}

func formatRDAPIP(o *rdapObject, source string) string {
	var w kvWriter
	w.add("Network", o.Name)
	w.add("Handle", o.Handle)
	if o.StartAddress != "" || o.EndAddress != "" {
		w.add("Range", o.StartAddress+" - "+o.EndAddress)
	}
	var cidrs []string
	for _, c := range o.Cidrs {
		p := c.V4Prefix
		if p == "" {
			p = c.V6Prefix
		}
		if p != "" {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", p, c.Length))
		}
	}
	w.add("CIDR", strings.Join(cidrs, ", "))
	w.add("Type", o.Type)
	w.add("Country", o.Country)
	org := findEntity(o.Entities, "registrant")
	if org == nil {
		org = findEntity(o.Entities, "administrative")
	}
	w.add("Organization", entityName(org))
	w.add("Status", strings.Join(o.Status, ", "))
	w.add("Created", eventDate(o.Events, "registration"))
	w.add("Updated", eventDate(o.Events, "last changed"))
	if abuse := findEntity(o.Entities, "abuse"); abuse != nil {
		w.add("Abuse", vcardField(abuse.VCardArray, "email"))
	}
	w.add("Source", source)
	return w.String()
}

func init() {
	RegisterProvider(&RDAPProvider{})
}
