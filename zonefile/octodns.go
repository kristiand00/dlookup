package zonefile

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// octoRecord is one record (set) of an OctoDNS YAML zone.
type octoRecord struct {
	Octodns map[string]any `yaml:"octodns,omitempty"`
	TTL     uint32         `yaml:"ttl,omitempty"`
	Type    string         `yaml:"type"`
	Value   any            `yaml:"value,omitempty"`
	Values  []any          `yaml:"values,omitempty"`
}

type octoMX struct {
	Exchange   string `yaml:"exchange"`
	Preference uint16 `yaml:"preference"`
}

type octoSRV struct {
	Port     uint16 `yaml:"port"`
	Priority uint16 `yaml:"priority"`
	Target   string `yaml:"target"`
	Weight   uint16 `yaml:"weight"`
}

type octoCAA struct {
	Flags uint8  `yaml:"flags"`
	Tag   string `yaml:"tag"`
	Value string `yaml:"value"`
}

type octoSSHFP struct {
	Algorithm       uint8  `yaml:"algorithm"`
	Fingerprint     string `yaml:"fingerprint"`
	FingerprintType uint8  `yaml:"fingerprint_type"`
}

type octoTLSA struct {
	CertificateAssociationData string `yaml:"certificate_association_data"`
	CertificateUsage           uint8  `yaml:"certificate_usage"`
	MatchingType               uint8  `yaml:"matching_type"`
	Selector                   uint8  `yaml:"selector"`
}

type octoDS struct {
	Algorithm  uint8  `yaml:"algorithm"`
	Digest     string `yaml:"digest"`
	DigestType uint8  `yaml:"digest_type"`
	KeyTag     uint16 `yaml:"key_tag"`
}

type octoNAPTR struct {
	Flags       string `yaml:"flags"`
	Order       uint16 `yaml:"order"`
	Preference  uint16 `yaml:"preference"`
	Regexp      string `yaml:"regexp"`
	Replacement string `yaml:"replacement"`
	Service     string `yaml:"service"`
}

// octoName types take a single domain name value.
var octoName = map[string]bool{"CNAME": true, "ALIAS": true, "DNAME": true, "NS": true, "PTR": true}

func parseOctoDNS(r io.Reader, origin string) (*Zone, error) {
	if origin == "" {
		return nil, fmt.Errorf("OctoDNS files do not name their zone; specify the origin")
	}
	var doc map[string]any
	if err := yaml.NewDecoder(r).Decode(&doc); err != nil && err != io.EOF {
		return nil, err
	}
	z := &Zone{Origin: origin}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var items []any
		switch v := doc[key].(type) {
		case []any:
			items = v
		case map[string]any:
			items = []any{v}
		case nil:
			continue
		default:
			return nil, fmt.Errorf("%q: expected a record or a list of records", key)
		}
		name := origin
		if key != "" {
			if strings.HasSuffix(key, ".") {
				name = Fqdn(key)
			} else {
				name = Fqdn(key + "." + origin)
			}
		}
		for _, it := range items {
			m, ok := it.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%q: expected a record mapping", key)
			}
			recs, err := octoToRecords(name, m)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", key, err)
			}
			z.Records = append(z.Records, recs...)
		}
	}
	return z, nil
}

func octoToRecords(name string, m map[string]any) ([]Record, error) {
	typ := strings.ToUpper(fmt.Sprint(m["type"]))
	if typ == "" || typ == "<NIL>" {
		return nil, fmt.Errorf("record without type")
	}
	var ttl uint32
	if t, ok := m["ttl"]; ok {
		n, err := strconv.ParseUint(fmt.Sprint(t), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl %v", t)
		}
		ttl = uint32(n)
	}
	var proxied *bool
	if o, ok := m["octodns"].(map[string]any); ok {
		if cf, ok := o["cloudflare"].(map[string]any); ok {
			if p, ok := cf["proxied"].(bool); ok {
				proxied = &p
			}
		}
	}
	var vals []any
	if v, ok := m["values"]; ok {
		list, ok := v.([]any)
		if !ok {
			list = []any{v}
		}
		vals = list
	} else if v, ok := m["value"]; ok {
		vals = []any{v}
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("%s record without value", typ)
	}
	var out []Record
	for _, v := range vals {
		data, err := octoValueToData(typ, v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", typ, err)
		}
		out = append(out, Record{Name: name, Type: typ, TTL: ttl, Data: data, Proxied: proxied})
	}
	return out, nil
}

func octoValueToData(typ string, v any) (string, error) {
	if m, ok := v.(map[string]any); ok {
		g := func(keys ...string) string {
			for _, k := range keys {
				if x, ok := m[k]; ok && x != nil {
					return fmt.Sprint(x)
				}
			}
			return ""
		}
		switch typ {
		case "MX":
			return g("preference", "priority") + " " + Fqdn(g("exchange", "value")), nil
		case "SRV":
			return fmt.Sprintf("%s %s %s %s", g("priority"), g("weight"), g("port"), Fqdn(g("target"))), nil
		case "CAA":
			flags := g("flags")
			if flags == "" {
				flags = "0"
			}
			return fmt.Sprintf("%s %s %s", flags, g("tag"), QuoteTXT([]string{g("value")})), nil
		case "SSHFP":
			return fmt.Sprintf("%s %s %s", g("algorithm"), g("fingerprint_type"), g("fingerprint")), nil
		case "TLSA":
			return fmt.Sprintf("%s %s %s %s", g("certificate_usage"), g("selector"), g("matching_type"), g("certificate_association_data")), nil
		case "DS":
			return fmt.Sprintf("%s %s %s %s", g("key_tag", "flags"), g("algorithm"), g("digest_type"), g("digest", "public_key")), nil
		case "NAPTR":
			return fmt.Sprintf("%s %s %s %s %s %s", g("order"), g("preference"), QuoteTXT([]string{g("flags")}),
				QuoteTXT([]string{g("service")}), QuoteTXT([]string{g("regexp")}), Fqdn(g("replacement"))), nil
		}
		return "", fmt.Errorf("structured value not supported for this type")
	}
	s := fmt.Sprint(v)
	switch {
	case typ == "TXT" || typ == "SPF":
		s = strings.ReplaceAll(s, `\;`, ";")
		return QuoteTXT(splitLong([]string{s})), nil
	case octoName[typ]:
		return Fqdn(s), nil
	}
	return s, nil
}

func writeOctoDNS(w io.Writer, z *Zone, wr *writer) error {
	type setKey struct{ name, typ string }
	var order []setKey
	sets := map[setKey]*octoRecord{}
	for _, r := range z.Records {
		typ := r.Type
		if typ == AliasType && r.Name != z.Origin {
			wr.warn("octodns: %s ALIAS %s written as a CNAME (OctoDNS allows ALIAS only at the apex)", r.Name, r.Data)
			typ = "CNAME"
		}
		val, err := octoValue(typ, r, wr.origin)
		if err != nil {
			wr.skip(OctoDNS, r, err.Error())
			continue
		}
		k := setKey{relName(r.Name, z.Origin), typ}
		if k.name == "@" {
			k.name = ""
		}
		s, ok := sets[k]
		if !ok {
			s = &octoRecord{Type: typ, TTL: r.TTL}
			if s.TTL == 0 {
				s.TTL = wr.opts.DefaultTTL
			}
			if r.Proxied != nil && *r.Proxied && cfProxiable[typ] {
				s.Octodns = map[string]any{"cloudflare": map[string]any{"proxied": *r.Proxied}}
			}
			sets[k] = s
			order = append(order, k)
		} else if r.TTL != 0 && r.TTL != s.TTL {
			wr.warn("octodns: %s %s has differing TTLs; using %d", r.Name, typ, s.TTL)
		}
		s.Values = append(s.Values, val)
	}
	doc := map[string]any{}
	for _, k := range order {
		s := sets[k]
		if len(s.Values) == 1 {
			s.Value, s.Values = s.Values[0], nil
		}
		if prev, ok := doc[k.name]; ok {
			switch p := prev.(type) {
			case *octoRecord:
				doc[k.name] = []*octoRecord{p, s}
			case []*octoRecord:
				doc[k.name] = append(p, s)
			}
		} else {
			doc[k.name] = s
		}
	}
	if _, err := io.WriteString(w, "---\n"); err != nil {
		return err
	}
	if len(doc) == 0 {
		_, err := io.WriteString(w, "{}\n")
		return err
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return enc.Close()
}

// octoValue converts a record's data to an OctoDNS value.
func octoValue(typ string, r Record, origin string) (any, error) {
	switch typ {
	case "ALIAS", "CNAME":
		if r.Type == AliasType {
			return r.Data, nil
		}
	case "TXT", "SPF":
		return strings.ReplaceAll(TXTValue(r.Data), ";", `\;`), nil
	}
	rr, err := parseRR(r.Name, r.TTL, typ, r.Data, origin)
	if err != nil {
		return nil, err
	}
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String(), nil
	case *dns.AAAA:
		return v.AAAA.String(), nil
	case *dns.CNAME:
		return v.Target, nil
	case *dns.DNAME:
		return v.Target, nil
	case *dns.NS:
		return v.Ns, nil
	case *dns.PTR:
		return v.Ptr, nil
	case *dns.MX:
		return octoMX{Exchange: v.Mx, Preference: v.Preference}, nil
	case *dns.SRV:
		return octoSRV{Port: v.Port, Priority: v.Priority, Target: v.Target, Weight: v.Weight}, nil
	case *dns.CAA:
		return octoCAA{Flags: v.Flag, Tag: v.Tag, Value: v.Value}, nil
	case *dns.SSHFP:
		return octoSSHFP{Algorithm: v.Algorithm, FingerprintType: v.Type, Fingerprint: v.FingerPrint}, nil
	case *dns.TLSA:
		return octoTLSA{CertificateUsage: v.Usage, Selector: v.Selector, MatchingType: v.MatchingType, CertificateAssociationData: v.Certificate}, nil
	case *dns.DS:
		return octoDS{KeyTag: v.KeyTag, Algorithm: v.Algorithm, DigestType: v.DigestType, Digest: v.Digest}, nil
	case *dns.NAPTR:
		return octoNAPTR{Order: v.Order, Preference: v.Preference, Flags: v.Flags, Service: v.Service, Regexp: v.Regexp, Replacement: v.Replacement}, nil
	}
	return nil, fmt.Errorf("type not supported by OctoDNS")
}
