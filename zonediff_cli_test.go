package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"dlookup/lookup"

	"github.com/miekg/dns"
)

func TestParseZoneDiffArgs(t *testing.T) {
	dir := t.TempDir()
	namesFile := filepath.Join(dir, "names.txt")
	if err := os.WriteFile(namesFile, []byte("# comment\nintranet\n\nvpn2.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	cfg, err := parseZoneDiffArgs([]string{
		"--new", "198.51.100.53:5353", "Example.COM", "--old", "192.0.2.53",
		"--names", "shop, api", "--names-file", namesFile, "--types", "a,mx,TXT",
		"--ttl", "--no-axfr", "--all", "-o", "json", "--timeout", "3s", "--concurrency", "2",
	}, strings.NewReader(""), &stderr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := lookup.ZoneDiffOptions{
		Domain:      "example.com",
		OldServer:   "192.0.2.53",
		NewServer:   "198.51.100.53:5353",
		ExtraNames:  []string{"shop", "api", "intranet", "vpn2.example.com"},
		Types:       []uint16{dns.TypeA, dns.TypeMX, dns.TypeTXT},
		CompareTTL:  true,
		TryAXFR:     false,
		Timeout:     3 * time.Second,
		Concurrency: 2,
	}
	if !reflect.DeepEqual(cfg.Opts, want) {
		t.Errorf("Opts = %+v\nwant  %+v", cfg.Opts, want)
	}
	if cfg.Output != outputJSON || !cfg.ShowAll {
		t.Errorf("Output=%q ShowAll=%v", cfg.Output, cfg.ShowAll)
	}

	// Defaults.
	cfg, err = parseZoneDiffArgs([]string{"example.com", "--new", "ns1.new.example"}, nil, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Opts.TryAXFR || cfg.Opts.Types != nil || cfg.Output != outputText || cfg.Opts.Timeout != defaultZoneDiffTimeout || cfg.Opts.Concurrency != defaultConcurrency {
		t.Errorf("defaults: %+v output=%q", cfg.Opts, cfg.Output)
	}

	bad := [][]string{
		{},
		{"example.com"},                        // no --new
		{"--new", "1.1.1.1"},                   // no domain
		{"a.com", "b.com", "--new", "1.1.1.1"}, // two domains
		{"-bad", "--new", "1.1.1.1"},           // unknown flag
		{"example.com", "--new", "1.1.1.1:99999"}, // bad port
		{"example.com", "--new", "1.1.1.1", "--old", "-x"},
		{"example.com", "--new", "1.1.1.1", "--types", "A,BOGUS"},
		{"example.com", "--new", "1.1.1.1", "--types", "ANY"},
		{"example.com", "--new", "1.1.1.1", "-o", "xml"},
		{"example.com", "--new", "1.1.1.1", "--concurrency", "0"},
		{"example.com", "--new", "1.1.1.1", "--timeout", "0s"},
		{"example.com", "--new", "1.1.1.1", "--names", "bad name"},
		{"example.com", "--new", "1.1.1.1", "--names-file", filepath.Join(dir, "missing")},
	}
	for _, args := range bad {
		if _, err := parseZoneDiffArgs(args, nil, &stderr); !errors.Is(err, errUsage) {
			t.Errorf("%q: err = %v, want usage error", args, err)
		}
	}
}

func withFakeDiffZone(t *testing.T, f func(ctx context.Context, opts lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error)) {
	t.Helper()
	orig := diffZone
	diffZone = f
	t.Cleanup(func() { diffZone = orig })
}

func fakeResult(statuses ...lookup.DiffStatus) *lookup.ZoneDiffResult {
	r := &lookup.ZoneDiffResult{
		Domain: "example.com.", OldServers: []string{"192.0.2.53:53"}, NewServer: "198.51.100.53:53",
		Enumeration: "probe (3 names)", Counts: map[lookup.DiffStatus]int{},
	}
	for i, s := range statuses {
		r.Records = append(r.Records, lookup.RecordDiff{
			Name: []string{"example.com.", "www.example.com.", "shop.example.com."}[i%3], Type: "A",
			Status: s, Old: []string{"192.0.2.1"}, New: []string{"192.0.2.2"},
		})
		r.Counts[s]++
	}
	return r
}

func TestRunZoneDiffExitCodes(t *testing.T) {
	var gotOpts lookup.ZoneDiffOptions
	var result *lookup.ZoneDiffResult
	var resultErr error
	withFakeDiffZone(t, func(ctx context.Context, opts lookup.ZoneDiffOptions) (*lookup.ZoneDiffResult, error) {
		gotOpts = opts
		return result, resultErr
	})

	run1 := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"zonediff"}, args...), strings.NewReader(""), &out, &errb)
		return code, out.String(), errb.String()
	}

	result = fakeResult(lookup.DiffMatch)
	code, out, _ := run1("example.com", "--new", "198.51.100.53")
	if code != 0 || !strings.Contains(out, "No differences found.") {
		t.Errorf("match: code=%d out=%q", code, out)
	}
	if gotOpts.Domain != "example.com" || gotOpts.NewServer != "198.51.100.53" || gotOpts.Progress != nil {
		t.Errorf("opts = %+v", gotOpts)
	}

	result = fakeResult(lookup.DiffMatch, lookup.DiffChanged, lookup.DiffMissing)
	code, out, _ = run1("--new", "198.51.100.53", "example.com")
	if code != 1 || !strings.Contains(out, "~ www.example.com. A") || !strings.Contains(out, "- shop.example.com. A") {
		t.Errorf("diff: code=%d out=%q", code, out)
	}

	code, out, _ = run1("--new", "198.51.100.53", "example.com", "-o", "json")
	var decoded struct {
		Records []struct{ Status string } `json:"records"`
		Counts  map[string]int            `json:"counts"`
	}
	if code != 1 || json.Unmarshal([]byte(out), &decoded) != nil || decoded.Records[1].Status != "changed" || decoded.Counts["missing"] != 1 {
		t.Errorf("json: code=%d out=%q", code, out)
	}

	code, _, errOut := run1("example.com")
	if code != 2 || !strings.Contains(errOut, "--new") {
		t.Errorf("usage: code=%d stderr=%q", code, errOut)
	}

	resultErr, result = errors.New("unreachable"), nil
	code, _, errOut = run1("example.com", "--new", "198.51.100.53")
	if code != 3 || !strings.Contains(errOut, "unreachable") {
		t.Errorf("runtime: code=%d stderr=%q", code, errOut)
	}

	code, _, errOut = run1("--help")
	if code != 0 || !strings.Contains(errOut, "dlookup zonediff <domain> --new <server>") || !strings.Contains(errOut, "--names-file") {
		t.Errorf("help: code=%d stderr=%q", code, errOut)
	}
}

func TestMainHelpMentionsZoneDiff(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--help"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(errb.String(), "dlookup zonediff") {
		t.Errorf("main help does not mention zonediff:\n%s", errb.String())
	}
}
