package lookup

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// MaxTargetLength is the maximum length of a domain name in presentation
// format (RFC 1035 §2.3.4, without the trailing root dot).
const MaxTargetLength = 253

// idnaProfile converts individual Unicode labels to their A-label (punycode)
// form. It is deliberately lenient about STD3 rules because we validate the
// ASCII character set ourselves (allowing '_' for names like _dmarc.example.com).
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// ValidateTarget checks that s is an acceptable lookup target: an IPv4
// address, an IPv6 address, or a hostname (Unicode/IDN labels allowed).
// Surrounding whitespace is ignored; whitespace or control characters inside
// the target, a leading '-' or '+', and names longer than 253 characters are
// rejected. Besides catching typos, this prevents a target from being
// interpreted as an option by external commands (dig/nslookup/whois).
func ValidateTarget(s string) error {
	_, err := normalizeTarget(s)
	return err
}

// NormalizeTarget validates s (see ValidateTarget) and returns it in the form
// used on the wire: IPs unchanged, hostnames lower-cased ASCII (IDN labels
// converted to punycode) without a trailing dot.
func NormalizeTarget(s string) (string, error) {
	return normalizeTarget(s)
}

func normalizeTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("target must not be empty")
	}
	if s[0] == '-' || s[0] == '+' {
		return "", fmt.Errorf("invalid target %q: must not start with %q", s, s[0])
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("invalid target %q: contains whitespace or control characters", s)
		}
	}
	if len(s) > 4*MaxTargetLength { // cheap upper bound before IDNA work
		return "", fmt.Errorf("invalid target: longer than %d characters", MaxTargetLength)
	}
	if ip := net.ParseIP(s); ip != nil {
		return s, nil
	}

	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return "", fmt.Errorf("invalid target %q", s)
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		ascii, err := validateLabel(label)
		if err != nil {
			return "", fmt.Errorf("invalid target %q: %w", s, err)
		}
		labels[i] = ascii
	}
	if isAllDigits(labels[len(labels)-1]) {
		// e.g. "300.1.1.1" or "1.2.3": looks like a mistyped IP, not a hostname.
		return "", fmt.Errorf("invalid target %q: not a valid IP address or hostname", s)
	}
	out := strings.Join(labels, ".")
	if len(out) > MaxTargetLength {
		return "", fmt.Errorf("invalid target: longer than %d characters", MaxTargetLength)
	}
	return out, nil
}

// validateLabel checks one DNS label and returns its lower-case ASCII form.
func validateLabel(label string) (string, error) {
	if label == "" {
		return "", errors.New("empty label")
	}
	if !isASCII(label) {
		a, err := idnaProfile.ToASCII(label)
		if err != nil {
			return "", fmt.Errorf("invalid internationalized label %q: %v", label, err)
		}
		label = a
	}
	if len(label) > 63 {
		return "", fmt.Errorf("label %q longer than 63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return "", fmt.Errorf("label %q must not start or end with '-'", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", fmt.Errorf("label %q contains invalid character %q", label, c)
		}
	}
	return strings.ToLower(label), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// ValidateServer checks a DNS server given as "host", "host:port", "[v6]:port"
// or a bare IPv6 address. The host must pass ValidateTarget and the port, if
// present, must be 1-65535.
func ValidateServer(server string) error {
	server = strings.TrimSpace(server)
	host, port := server, ""
	if h, p, err := net.SplitHostPort(server); err == nil {
		host, port = h, p
	}
	host = strings.Trim(host, "[]")
	if err := ValidateTarget(host); err != nil {
		return fmt.Errorf("invalid DNS server %q: %w", server, err)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid DNS server %q: bad port %q", server, port)
		}
	}
	return nil
}
