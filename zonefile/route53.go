package zonefile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

type r53Value struct {
	Value string `json:"Value"`
}

type r53Alias struct {
	HostedZoneId         string `json:"HostedZoneId"`
	DNSName              string `json:"DNSName"`
	EvaluateTargetHealth bool   `json:"EvaluateTargetHealth"`
}

type r53RRSet struct {
	Name             string      `json:"Name"`
	Type             string      `json:"Type"`
	SetIdentifier    string      `json:"SetIdentifier,omitempty"`
	Weight           *int64      `json:"Weight,omitempty"`
	Region           string      `json:"Region,omitempty"`
	Failover         string      `json:"Failover,omitempty"`
	MultiValueAnswer *bool       `json:"MultiValueAnswer,omitempty"`
	TTL              *uint32     `json:"TTL,omitempty"`
	ResourceRecords  []r53Value  `json:"ResourceRecords,omitempty"`
	AliasTarget      *r53Alias   `json:"AliasTarget,omitempty"`
	HealthCheckId    string      `json:"HealthCheckId,omitempty"`
	GeoLocation      interface{} `json:"GeoLocation,omitempty"`
}

type r53Change struct {
	Action            string   `json:"Action"`
	ResourceRecordSet r53RRSet `json:"ResourceRecordSet"`
}

type r53ChangeBatch struct {
	Comment string      `json:"Comment,omitempty"`
	Changes []r53Change `json:"Changes"`
}

// route53Types are the record types Route 53 supports.
var route53Types = map[string]bool{
	"A": true, "AAAA": true, "CAA": true, "CNAME": true, "DS": true, "HTTPS": true, "MX": true,
	"NAPTR": true, "NS": true, "PTR": true, "SOA": true, "SPF": true, "SRV": true, "SSHFP": true,
	"SVCB": true, "TLSA": true, "TXT": true,
}

// r53MetaPrefix starts the comment that carries Route 53-only settings.
const r53MetaPrefix = "route53:"

// DecodeRoute53Name decodes Route 53's octal escapes ("\052" is "*").
func DecodeRoute53Name(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v, _ := strconv.ParseUint(s[i+1:i+4], 8, 8)
			b.WriteByte(byte(v))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// encodeRoute53Name escapes "*" as Route 53 lists it.
func encodeRoute53Name(s string) string { return strings.ReplaceAll(s, "*", `\052`) }

func parseRoute53(r io.Reader, origin string) (*Zone, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	var sets []r53RRSet
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &sets); err != nil {
			return nil, err
		}
	} else {
		var doc struct {
			ResourceRecordSets []r53RRSet      `json:"ResourceRecordSets"`
			Changes            []r53Change     `json:"Changes"`
			ChangeBatch        *r53ChangeBatch `json:"ChangeBatch"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		sets = doc.ResourceRecordSets
		changes := doc.Changes
		if doc.ChangeBatch != nil {
			changes = append(changes, doc.ChangeBatch.Changes...)
		}
		for _, c := range changes {
			if strings.EqualFold(c.Action, "DELETE") {
				continue
			}
			sets = append(sets, c.ResourceRecordSet)
		}
	}
	z := &Zone{Origin: origin}
	for _, s := range sets {
		name := Fqdn(DecodeRoute53Name(s.Name))
		typ := strings.ToUpper(s.Type)
		var ttl uint32
		if s.TTL != nil {
			ttl = *s.TTL
		}
		meta := r53Meta(s)
		if s.AliasTarget != nil {
			m := append([]string{"alias-type=" + typ, "alias-zone=" + s.AliasTarget.HostedZoneId,
				"evaluate-target-health=" + strconv.FormatBool(s.AliasTarget.EvaluateTargetHealth)}, meta...)
			z.Records = append(z.Records, Record{
				Name:    name,
				Type:    AliasType,
				Data:    Fqdn(DecodeRoute53Name(s.AliasTarget.DNSName)),
				Comment: r53MetaPrefix + " " + strings.Join(m, " "),
			})
			continue
		}
		comment := ""
		if len(meta) > 0 {
			comment = r53MetaPrefix + " " + strings.Join(meta, " ")
		}
		for _, v := range s.ResourceRecords {
			z.Records = append(z.Records, Record{Name: name, Type: typ, TTL: ttl, Data: v.Value, Comment: comment})
		}
	}
	return z, nil
}

// r53Meta lists a record set's routing settings as key=value pairs.
func r53Meta(s r53RRSet) []string {
	var m []string
	if s.SetIdentifier != "" {
		m = append(m, "set-id="+strings.ReplaceAll(s.SetIdentifier, " ", "_"))
	}
	if s.Weight != nil {
		m = append(m, "weight="+strconv.FormatInt(*s.Weight, 10))
	}
	if s.Region != "" {
		m = append(m, "region="+s.Region)
	}
	if s.Failover != "" {
		m = append(m, "failover="+s.Failover)
	}
	if s.MultiValueAnswer != nil {
		m = append(m, "multivalue="+strconv.FormatBool(*s.MultiValueAnswer))
	}
	if s.HealthCheckId != "" {
		m = append(m, "health-check="+s.HealthCheckId)
	}
	return m
}

// parseR53Meta reads the key=value pairs of a "route53: ..." comment.
func parseR53Meta(comment string) map[string]string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(comment), r53MetaPrefix)
	if !ok {
		return nil
	}
	m := map[string]string{}
	for _, kv := range strings.Fields(rest) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// r53Sets groups records into Route 53 record sets.
func r53Sets(z *Zone, wr *writer, f Format, escapeNames bool) []r53RRSet {
	var (
		order []string
		sets  = map[string]*r53RRSet{}
	)
	for _, r := range z.Records {
		meta := parseR53Meta(r.Comment)
		name := r.Name
		if escapeNames {
			name = encodeRoute53Name(name)
		}
		if r.Type == AliasType {
			zoneID := meta["alias-zone"]
			if zoneID == "" && wr.opts.Route53ZoneID != "" && (r.Data == z.Origin || strings.HasSuffix(r.Data, "."+z.Origin)) {
				zoneID = wr.opts.Route53ZoneID
			}
			if zoneID == "" {
				wr.skip(f, r, "alias target hosted zone id unknown")
				continue
			}
			typ := meta["alias-type"]
			if typ == "" {
				typ = "A"
			}
			s := r53RRSet{Name: name, Type: typ, AliasTarget: &r53Alias{
				HostedZoneId: zoneID, DNSName: r.Data, EvaluateTargetHealth: meta["evaluate-target-health"] == "true",
			}}
			applyR53Meta(&s, meta)
			key := name + "\x00" + typ + "\x00" + s.SetIdentifier
			if _, dup := sets[key]; dup {
				wr.skip(f, r, "duplicate alias record set")
				continue
			}
			order = append(order, key)
			sets[key] = &s
			continue
		}
		if !route53Types[r.Type] {
			wr.skip(f, r, "type not supported by Route 53")
			continue
		}
		key := name + "\x00" + r.Type + "\x00" + meta["set-id"]
		s, ok := sets[key]
		if !ok {
			ttl := wr.ttl(r, 300)
			s = &r53RRSet{Name: name, Type: r.Type, TTL: &ttl}
			applyR53Meta(s, meta)
			sets[key] = s
			order = append(order, key)
		} else if r.TTL != 0 && *s.TTL != r.TTL {
			wr.warn("%s: %s %s has differing TTLs; using %d for the record set", f, r.Name, r.Type, *s.TTL)
		}
		if s.AliasTarget != nil {
			wr.skip(f, r, "conflicts with an alias record set")
			continue
		}
		s.ResourceRecords = append(s.ResourceRecords, r53Value{Value: r.Data})
	}
	out := make([]r53RRSet, 0, len(order))
	for _, k := range order {
		out = append(out, *sets[k])
	}
	return out
}

func applyR53Meta(s *r53RRSet, meta map[string]string) {
	s.SetIdentifier = meta["set-id"]
	if v, err := strconv.ParseInt(meta["weight"], 10, 64); err == nil {
		s.Weight = &v
	}
	s.Region = meta["region"]
	s.Failover = meta["failover"]
	if v, ok := meta["multivalue"]; ok {
		b := v == "true"
		s.MultiValueAnswer = &b
	}
	s.HealthCheckId = meta["health-check"]
}

func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func writeRoute53List(w io.Writer, z *Zone, wr *writer) error {
	sets := r53Sets(z, wr, Route53, true)
	if sets == nil {
		sets = []r53RRSet{}
	}
	return encodeJSON(w, struct {
		ResourceRecordSets []r53RRSet `json:"ResourceRecordSets"`
	}{sets})
}

func writeRoute53Change(w io.Writer, z *Zone, wr *writer) error {
	action := strings.ToUpper(strings.TrimSpace(wr.opts.Route53Action))
	if action == "" {
		action = "UPSERT"
	}
	switch action {
	case "CREATE", "UPSERT", "DELETE":
	default:
		return fmt.Errorf("invalid Route 53 action %q (want CREATE, UPSERT or DELETE)", action)
	}
	sets := r53Sets(z, wr, Route53Change, false)
	// Route 53 needs an alias target's record set to exist first; put
	// aliases last.
	sort.SliceStable(sets, func(i, j int) bool { return sets[i].AliasTarget == nil && sets[j].AliasTarget != nil })
	batch := r53ChangeBatch{Comment: "Import of " + strings.TrimSuffix(z.Origin, ".") + " by dlookup", Changes: []r53Change{}}
	if wr.opts.Route53ZoneID != "" {
		batch.Comment += " into hosted zone " + wr.opts.Route53ZoneID
	}
	for _, s := range sets {
		batch.Changes = append(batch.Changes, r53Change{Action: action, ResourceRecordSet: s})
	}
	return encodeJSON(w, batch)
}
