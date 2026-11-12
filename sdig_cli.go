package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"dlookup/lookup"
)

// "dlookup sdig ..." mimics PowerDNS's sdig (pdns/sdig.cc): the same argument
// grammar, the same output on stdout/stderr and the same exit codes (1 for
// usage errors; 0 otherwise, including "Fatal: ..." errors, as in sdig).

const sdigUsage = "sdig\n" +
	"Syntax: sdig IP-ADDRESS-OR-DOH-URL PORT QNAME QTYPE " +
	"[dnssec] [ednssubnet SUBNET/MASK] [hidesoadetails] [hidettl] [recurse] [showflags] " +
	"[tcp] [dot] [insecure] [fastOpen] [subjectName name] [caStore file] [tlsProvider openssl|gnutls] " +
	"[proxy UDP(0)/TCP(1) SOURCE-IP-ADDRESS-AND-PORT DESTINATION-IP-ADDRESS-AND-PORT] " +
	"[cookie -/HEX] " +
	"[dumpluaraw] [opcode OPNUM] " +
	"[traceid -/HEX]\n"

// sdigGetenv is os.Getenv, replaceable in tests ($SDIGBUFSIZE).
var sdigGetenv = os.Getenv

// sdigExchange sends a query; replaceable in tests.
var sdigExchange = lookup.SDIGExchange

// sdigArgs is a parsed sdig command line.
type sdigArgs struct {
	server, port, name, qtype string
	req                       lookup.SDIGRequest
	format                    lookup.SDIGFormat
	warnings                  []string // printed to stderr before querying
}

// atoi behaves like C's atoi: leading whitespace, optional sign, digits; 0 otherwise.
func atoi(s string) int {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	end := 0
	if end < len(s) && (s[end] == '-' || s[end] == '+') {
		end++
	}
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

// errSDIGExit carries an sdig exit code with the message to print to stderr.
type errSDIGExit struct {
	code int
	msg  string
}

func (e errSDIGExit) Error() string { return e.msg }

// parseSDIGArgs parses args (without "sdig") with sdig's grammar. Errors are
// errSDIGExit values; "Fatal" ones exit 0.
func parseSDIGArgs(args []string) (*sdigArgs, error) {
	usage := errSDIGExit{1, sdigUsage}
	if len(args) < 4 {
		return nil, usage
	}
	a := &sdigArgs{server: args[0], port: args[1], name: args[2], qtype: args[3]}
	var dot bool
	var ednssubnet, cookie *string
	need := func(i int, n int, what string) error {
		if i+n >= len(args) {
			return errSDIGExit{1, what + " needs an argument\n"}
		}
		return nil
	}
	for i := 4; i < len(args); i++ {
		switch opt := args[i]; opt {
		case "dnssec":
			a.req.DNSSEC = true
		case "recurse":
			a.req.Recurse = true
		case "showflags":
			a.format.ShowFlags = true
		case "hidesoadetails":
			a.format.HideSOADetails = true
		case "hidettl":
			a.format.HideTTL = true
		case "tcp":
			a.req.TCP = true
		case "dot":
			dot = true
		case "insecure":
			a.req.Insecure = true
		case "fastOpen":
			// TCP Fast Open is an optimisation; ignored.
		case "ednssubnet":
			if err := need(i, 1, opt); err != nil {
				return nil, err
			}
			i++
			ednssubnet = &args[i]
		case "class":
			if err := need(i, 1, opt); err != nil {
				return nil, err
			}
			i++
			a.req.Class = uint16(atoi(args[i]))
		case "opcode":
			if err := need(i, 1, opt); err != nil {
				return nil, err
			}
			i++
			a.req.Opcode = int(uint8(atoi(args[i])))
		case "subjectName":
			if err := need(i, 1, opt); err != nil {
				return nil, err
			}
			i++
			a.req.SubjectName = args[i]
		case "caStore":
			if err := need(i, 1, opt); err != nil {
				return nil, err
			}
			i++
			a.req.CAStore = args[i]
		case "tlsProvider":
			if err := need(i, 1, opt); err != nil {
				return nil, err
			}
			i++ // Go's crypto/tls is always used.
		case "cookie":
			if err := need(i, 1, opt); err != nil {
				return nil, err
			}
			i++
			cookie = &args[i]
		case "proxy", "dumpluaraw", "traceid":
			return nil, errSDIGExit{1, opt + ": not supported by dlookup sdig\n"}
		default:
			return nil, errSDIGExit{1, opt + ": unknown argument\n"}
		}
	}
	if dot {
		a.req.TCP, a.req.DoT = true, true
	}
	// Errors from here on are thrown inside sdig's try block: "Fatal", exit 0.
	fatal := func(format string, v ...any) error {
		return errSDIGExit{0, "Fatal: " + fmt.Sprintf(format, v...) + "\n"}
	}
	if ednssubnet != nil {
		n, err := lookup.ParseNetmask(*ednssubnet)
		if err != nil {
			return nil, fatal("%v", err)
		}
		a.req.ECS = n
	}
	if cookie != nil {
		if *cookie == "-" {
			a.req.Cookie = lookup.RandomCookie()
		} else {
			b, _ := hex.DecodeString(*cookie)
			if b == nil {
				b = []byte{}
			}
			if n := len(b); n != 8 && (n < 16 || n > 40) {
				a.warnings = append(a.warnings, "Malformed cookie in argument list, adding anyway")
			}
			a.req.Cookie = b
		}
	}
	if s := sdigGetenv("SDIGBUFSIZE"); s != "" {
		a.req.ForceEDNS = true
		a.req.BufSize = uint16(atoi(s))
	}

	switch {
	case strings.HasPrefix(a.server, "h"):
		a.req.Server = a.server // DoH URL
	case a.server == "stdin":
		return nil, errSDIGExit{1, "stdin: not supported by dlookup sdig\n"}
	default:
		addr, err := sdigComboAddress(strings.TrimPrefix(a.server, "@"), atoi(a.port))
		if err != nil {
			return nil, fatal("%v", err)
		}
		a.req.Server = addr
	}
	if a.name == "-" && a.qtype == "-" && !a.req.TCP {
		return nil, fatal("multi-query from stdin only supported for tcp")
	}
	return a, nil
}

// sdigComboAddress parses an IP address (optionally with its own port, which
// overrides port) like PowerDNS's ComboAddress.
func sdigComboAddress(s string, port int) (string, error) {
	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(ip.String(), strconv.Itoa(port&0xffff)), nil
	}
	if host, p, err := net.SplitHostPort(s); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
				return net.JoinHostPort(ip.String(), p), nil
			}
		}
	}
	return "", fmt.Errorf("Unable to convert presentation address '%s'", s) //nolint:staticcheck // sdig's exact message
}

// runSDIG runs "dlookup sdig ..." and returns the exit code.
func runSDIG(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	for _, a := range args {
		switch a {
		case "--help":
			fmt.Fprint(stderr, sdigUsage)
			return 0
		case "--version":
			fmt.Fprintf(stderr, "sdig %s (dlookup)\n", versionString())
			return 0
		}
	}
	sa, err := parseSDIGArgs(args)
	if err != nil {
		e := err.(errSDIGExit)
		fmt.Fprint(stderr, e.msg)
		return e.code
	}

	for _, w := range sa.warnings {
		fmt.Fprintln(stderr, w)
	}
	questions := [][2]string{{sa.name, sa.qtype}}
	if sa.name == "-" && sa.qtype == "-" {
		questions = nil
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			name, typ, _ := strings.Cut(sc.Text(), " ")
			questions = append(questions, [2]string{name, typ})
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	for _, q := range questions {
		qtype, err := lookup.ParseQType(q[1])
		if err != nil {
			fmt.Fprintf(stderr, "Fatal: %v\n", err)
			return 0
		}
		req := sa.req
		req.Name, req.QType = q[0], qtype
		resp, err := sdigExchange(ctx, req)
		if err != nil {
			fmt.Fprintf(stderr, "Fatal: %v\n", err)
			return 0
		}
		out, ednsLines := lookup.FormatSDIG(resp, sa.format)
		fmt.Fprint(stdout, out)
		for _, l := range ednsLines {
			fmt.Fprintln(stderr, l)
		}
	}
	return 0
}
