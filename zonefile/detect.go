package zonefile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Detect guesses the format of a file from its name and (if data is not
// empty) its content. Content wins over the extension for JSON files, which
// several formats share. With no data (e.g. an output file) hints in the
// name are used: "route53"/"r53", "change", "cloudflare"/"cf".
func Detect(filename string, data []byte) (Format, error) {
	base := strings.ToLower(filepath.Base(filename))
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	hasData := len(bytes.TrimSpace(data)) > 0
	hint := func(words ...string) bool {
		for _, w := range words {
			if regexp.MustCompile(`(^|[^a-z0-9])` + regexp.QuoteMeta(w) + `($|[^a-z0-9])`).MatchString(stem) {
				return true
			}
		}
		return false
	}

	switch ext {
	case ".zone", ".db", ".bind", ".hosts":
		return BIND, nil
	case ".yaml", ".yml":
		return OctoDNS, nil
	case ".csv":
		return CSV, nil
	case ".tf":
		if hint("cloudflare", "cf") {
			return TerraformCloudflare, nil
		}
		if hasData && bytes.Contains(data, []byte("cloudflare_dns_record")) {
			return TerraformCloudflare, nil
		}
		return Terraform, nil
	case ".js":
		return DNSControl, nil
	case ".json":
		if hasData {
			return sniffJSON(data)
		}
		switch {
		case hint("route53", "r53", "aws") && hint("change", "changes", "batch"):
			return Route53Change, nil
		case hint("route53", "r53", "aws"):
			return Route53, nil
		case hint("cloudflare", "cf"):
			return Cloudflare, nil
		}
		return JSON, nil
	}
	if !hasData {
		if ext == "" && hint("zone") || strings.HasPrefix(base, "db.") {
			return BIND, nil
		}
		return "", fmt.Errorf("cannot tell the format of %q from its name; specify it", filename)
	}
	return sniff(data)
}

// sniff guesses the format from content alone.
func sniff(data []byte) (Format, error) {
	t := bytes.TrimSpace(data)
	if len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		return sniffJSON(t)
	}
	text := string(t)
	first := strings.ToLower(strings.SplitN(text, "\n", 2)[0])
	switch {
	case strings.Contains(text, "$ORIGIN") || strings.Contains(text, "$TTL") ||
		regexp.MustCompile(`(?mi)\sIN\s+(SOA|NS|A|AAAA|MX|CNAME|TXT)\s`).MatchString(text):
		return BIND, nil
	case strings.HasPrefix(first, "name,") && strings.Contains(first, "type"):
		return CSV, nil
	case strings.HasPrefix(text, "---") || regexp.MustCompile(`(?m)^('[^']*'|"[^"]*"|[\w.*-]+):\s*$`).MatchString(text):
		return OctoDNS, nil
	case strings.Contains(text, "aws_route53_record"):
		return Terraform, nil
	case strings.Contains(text, "cloudflare_dns_record") || strings.Contains(text, "cloudflare_record"):
		return TerraformCloudflare, nil
	case strings.Contains(text, "D(") && strings.Contains(text, "END"):
		return DNSControl, nil
	}
	return "", fmt.Errorf("cannot detect the zone format; specify it")
}

// sniffJSON tells the JSON formats apart.
func sniffJSON(data []byte) (Format, error) {
	var probe any
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}
	switch v := probe.(type) {
	case []any:
		if len(v) == 0 {
			return Cloudflare, nil
		}
		if m, ok := v[0].(map[string]any); ok {
			if _, ok := m["content"]; ok {
				return Cloudflare, nil
			}
			if _, ok := m["ResourceRecords"]; ok {
				return Route53, nil
			}
			if _, ok := m["AliasTarget"]; ok {
				return Route53, nil
			}
		}
	case map[string]any:
		switch {
		case v["ResourceRecordSets"] != nil:
			return Route53, nil
		case v["Changes"] != nil:
			return Route53Change, nil
		case v["ChangeBatch"] != nil:
			return Route53Change, nil
		case v["result"] != nil:
			return Cloudflare, nil
		case v["records"] != nil || v["origin"] != nil:
			return JSON, nil
		}
	}
	return "", fmt.Errorf("unrecognized JSON zone format; specify it")
}
