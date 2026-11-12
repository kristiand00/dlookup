package zonefile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// cfRecord is one record of the Cloudflare API (GET /zones/:id/dns_records).
type cfRecord struct {
	ID       string         `json:"id,omitempty"`
	ZoneName string         `json:"zone_name,omitempty"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Content  string         `json:"content,omitempty"`
	TTL      uint32         `json:"ttl"`
	Proxied  *bool          `json:"proxied,omitempty"`
	Priority *uint16        `json:"priority,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	Comment  string         `json:"comment,omitempty"`
}

// cfTypes are the record types Cloudflare manages.
var cfTypes = map[string]bool{
	"A": true, "AAAA": true, "CAA": true, "CERT": true, "CNAME": true, "DNSKEY": true, "DS": true,
	"HTTPS": true, "LOC": true, "MX": true, "NAPTR": true, "NS": true, "OPENPGPKEY": true, "PTR": true,
	"SMIMEA": true, "SRV": true, "SSHFP": true, "SVCB": true, "TLSA": true, "TXT": true, "URI": true,
}

// cfProxiable are the types that can be proxied.
var cfProxiable = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

func parseCloudflare(r io.Reader, origin string) (*Zone, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	var recs []cfRecord
	if len(raw) > 0 && raw[0] == '[' {
		err = json.Unmarshal(raw, &recs)
	} else {
		var env struct {
			Success *bool            `json:"success"`
			Errors  []map[string]any `json:"errors"`
			Result  []cfRecord       `json:"result"`
		}
		err = json.Unmarshal(raw, &env)
		if err == nil && env.Success != nil && !*env.Success {
			return nil, fmt.Errorf("API response reports failure: %v", env.Errors)
		}
		recs = env.Result
	}
	if err != nil {
		return nil, err
	}
	z := &Zone{Origin: origin}
	for i, c := range recs {
		if z.Origin == "" && c.ZoneName != "" {
			z.Origin = Fqdn(c.ZoneName)
		}
		rec, err := cfToRecord(c)
		if err != nil {
			return nil, fmt.Errorf("record %d (%s %s): %w", i+1, c.Name, c.Type, err)
		}
		z.Records = append(z.Records, rec)
	}
	return z, nil
}

func cfNum(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64), true
	case string:
		return n, true
	case json.Number:
		return n.String(), true
	}
	return fmt.Sprint(v), true
}

func cfStr(m map[string]any, key string) string {
	s, _ := cfNum(m, key)
	return s
}

func cfToRecord(c cfRecord) (Record, error) {
	typ := strings.ToUpper(c.Type)
	rec := Record{Name: Fqdn(c.Name), Type: typ, TTL: c.TTL, Comment: c.Comment}
	if rec.TTL == 1 { // automatic
		rec.TTL = 0
	}
	if cfProxiable[typ] && c.Proxied != nil {
		v := *c.Proxied
		rec.Proxied = &v
	}
	prio := ""
	if c.Priority != nil {
		prio = strconv.Itoa(int(*c.Priority))
	}
	content := strings.TrimSpace(c.Content)
	d := c.Data
	switch typ {
	case "MX":
		if prio == "" {
			prio = "0"
		}
		rec.Data = prio + " " + Fqdn(content)
	case "CNAME", "NS", "PTR":
		rec.Data = Fqdn(content)
	case "TXT", "SPF":
		if strings.HasPrefix(content, `"`) {
			rec.Data = content
		} else {
			rec.Data = QuoteTXT(splitLong([]string{content}))
		}
	case "SRV":
		switch {
		case d != nil && cfStr(d, "target") != "":
			p := cfStr(d, "priority")
			if p == "" {
				p = prio
			}
			rec.Data = fmt.Sprintf("%s %s %s %s", p, cfStr(d, "weight"), cfStr(d, "port"), Fqdn(cfStr(d, "target")))
			// Legacy form: name is split into service/proto/name.
			if svc, proto := cfStr(d, "service"), cfStr(d, "proto"); svc != "" && proto != "" && !strings.HasPrefix(rec.Name, "_") {
				rec.Name = Fqdn(svc + "." + proto + "." + strings.TrimSuffix(cfStr(d, "name"), "."))
			}
		case len(strings.Fields(content)) == 3:
			rec.Data = prio + " " + content
		default:
			rec.Data = content
		}
		if f := strings.Fields(rec.Data); len(f) == 4 {
			rec.Data = strings.Join(f[:3], " ") + " " + Fqdn(f[3])
		}
	case "URI":
		if d != nil && cfStr(d, "target") != "" {
			p := cfStr(d, "priority")
			if p == "" {
				p = prio
			}
			rec.Data = fmt.Sprintf("%s %s %s", p, cfStr(d, "weight"), QuoteTXT([]string{cfStr(d, "target")}))
		} else if prio != "" && len(strings.Fields(content)) == 2 {
			rec.Data = prio + " " + content
		} else {
			rec.Data = content
		}
	case "CAA":
		if content == "" && d != nil {
			rec.Data = fmt.Sprintf("%s %s %s", cfStr(d, "flags"), cfStr(d, "tag"), QuoteTXT([]string{cfStr(d, "value")}))
		} else {
			rec.Data = fixCAA(content)
		}
	case "TLSA", "SMIMEA":
		if content == "" && d != nil {
			rec.Data = fmt.Sprintf("%s %s %s %s", cfStr(d, "usage"), cfStr(d, "selector"), cfStr(d, "matching_type"), cfStr(d, "certificate"))
		} else {
			rec.Data = content
		}
	case "SSHFP":
		if content == "" && d != nil {
			rec.Data = fmt.Sprintf("%s %s %s", cfStr(d, "algorithm"), cfStr(d, "type"), cfStr(d, "fingerprint"))
		} else {
			rec.Data = content
		}
	case "DS":
		if content == "" && d != nil {
			rec.Data = fmt.Sprintf("%s %s %s %s", cfStr(d, "key_tag"), cfStr(d, "algorithm"), cfStr(d, "digest_type"), cfStr(d, "digest"))
		} else {
			rec.Data = content
		}
	case "HTTPS", "SVCB":
		if content == "" && d != nil {
			rec.Data = strings.TrimSpace(fmt.Sprintf("%s %s %s", cfStr(d, "priority"), Fqdn(cfStr(d, "target")), cfStr(d, "value")))
		} else {
			rec.Data = content
		}
	default:
		rec.Data = content
	}
	if strings.TrimSpace(rec.Data) == "" {
		return rec, fmt.Errorf("no content")
	}
	return rec, nil
}

// fixCAA quotes an unquoted CAA value ("0 issue letsencrypt.org").
func fixCAA(s string) string {
	f := strings.SplitN(s, " ", 3)
	if len(f) == 3 && !strings.HasPrefix(f[2], `"`) {
		return f[0] + " " + f[1] + " " + QuoteTXT([]string{f[2]})
	}
	return s
}

// recordToCF converts a record to the Cloudflare API shape.
func recordToCF(r Record, wr *writer, f Format) (cfRecord, bool) {
	typ := r.Type
	if typ == AliasType {
		wr.warn("%s: %s ALIAS %s written as a CNAME (Cloudflare flattens CNAMEs at the apex)", f, r.Name, r.Data)
		typ = "CNAME"
	}
	if !cfTypes[typ] {
		wr.skip(f, r, "type not supported by Cloudflare")
		return cfRecord{}, false
	}
	c := cfRecord{Name: strings.TrimSuffix(r.Name, "."), Type: typ, TTL: r.TTL, Comment: r.Comment}
	if c.TTL == 0 {
		c.TTL = 1
		if wr.opts.DefaultTTL > 0 {
			c.TTL = wr.opts.DefaultTTL
		}
	}
	if cfProxiable[typ] {
		p := false
		if r.Proxied != nil {
			p = *r.Proxied
		}
		c.Proxied = &p
	}
	rr, err := parseRR(r.Name, r.TTL, typ, r.Data, wr.origin)
	if typ == "CNAME" && r.Type == AliasType {
		err = nil
		rr = nil
	}
	if err != nil {
		wr.skip(f, r, err.Error())
		return cfRecord{}, false
	}
	switch v := rr.(type) {
	case *dns.MX:
		c.Content = strings.TrimSuffix(v.Mx, ".")
		c.Priority = &v.Preference
	case *dns.CNAME:
		c.Content = strings.TrimSuffix(v.Target, ".")
	case *dns.NS:
		c.Content = strings.TrimSuffix(v.Ns, ".")
	case *dns.PTR:
		c.Content = strings.TrimSuffix(v.Ptr, ".")
	case *dns.TXT:
		strs := TXTStrings(r.Data)
		if len(strs) == 1 {
			c.Content = strs[0]
		} else {
			c.Content = r.Data
		}
	case *dns.SRV:
		c.Priority = &v.Priority
		c.Content = fmt.Sprintf("%d %d %s", v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
		c.Data = map[string]any{"priority": int64(v.Priority), "weight": int64(v.Weight), "port": int64(v.Port), "target": strings.TrimSuffix(v.Target, ".")}
	case *dns.URI:
		c.Priority = &v.Priority
		c.Content = fmt.Sprintf("%d %s", v.Weight, QuoteTXT([]string{v.Target}))
		c.Data = map[string]any{"weight": int64(v.Weight), "target": v.Target}
	case *dns.CAA:
		c.Content = r.Data
		c.Data = map[string]any{"flags": int64(v.Flag), "tag": v.Tag, "value": v.Value}
	default:
		if typ == "CNAME" { // from ALIAS
			c.Content = strings.TrimSuffix(r.Data, ".")
		} else {
			c.Content = r.Data
		}
	}
	return c, true
}

func writeCloudflare(w io.Writer, z *Zone, wr *writer) error {
	out := []cfRecord{}
	for _, r := range z.Records {
		if c, ok := recordToCF(r, wr, Cloudflare); ok {
			out = append(out, c)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
