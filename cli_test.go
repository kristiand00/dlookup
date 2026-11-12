package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dlookup/lookup"
)

// fakeProvider is a network-free provider registered only in tests.
// Targets containing "fail" return an error; "slow" targets sleep first.
type fakeProvider struct {
	mu        sync.Mutex
	inFlight  int
	maxFlight int
	lastOpts  lookup.Options
}

const fakeFlag = "zz-test-fake"
const fakeName = "ZZ Test Fake"

var fake = &fakeProvider{}

func init() { lookup.RegisterProvider(fake) }

func (f *fakeProvider) Name() string            { return fakeName }
func (f *fakeProvider) FlagName() string        { return fakeFlag }
func (f *fakeProvider) Usage() string           { return "fake lookup on domains from <filename>" }
func (f *fakeProvider) Command() string         { return "" }
func (f *fakeProvider) CheckAvailability() bool { return true }
func (f *fakeProvider) Execute(ctx context.Context, target string, opts lookup.Options) (string, error) {
	f.mu.Lock()
	f.inFlight++
	if f.inFlight > f.maxFlight {
		f.maxFlight = f.inFlight
	}
	f.lastOpts = opts
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if strings.Contains(target, "slow") {
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if strings.Contains(target, "fail") {
		return "partial " + target, fmt.Errorf("lookup of %s failed", target)
	}
	return "result for " + target, nil
}

func (f *fakeProvider) resetStats() {
	f.mu.Lock()
	f.inFlight, f.maxFlight = 0, 0
	f.mu.Unlock()
}

// withValidator replaces validateTarget for the duration of a test:
// targets starting with "bad" are rejected.
func withValidator(t *testing.T) {
	t.Helper()
	old := validateTarget
	validateTarget = func(s string) error {
		if strings.HasPrefix(s, "bad") {
			return errors.New("bad target")
		}
		return old(s)
	}
	t.Cleanup(func() { validateTarget = old })
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseArgsPositionalTUI(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{"example.com", "1.1.1.1"}, strings.NewReader(""), &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Headless() || cfg.Provider != nil || cfg.LookupType() != "" {
		t.Errorf("expected TUI mode without lookup type, got %+v", cfg)
	}
	if want := []string{"example.com", "1.1.1.1"}; !reflect.DeepEqual(cfg.Targets, want) {
		t.Errorf("targets = %v, want %v", cfg.Targets, want)
	}
}

func TestParseArgsFileThenPositionalAndStdin(t *testing.T) {
	path := writeFile(t, "# comment\na.com\n\n  b.com  \n")
	cfg, err := parseArgs([]string{"--" + fakeFlag, path, "extra.com", "-", "last.com"},
		strings.NewReader("s1.com\ns2.com\n"), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LookupType() != fakeName {
		t.Errorf("lookup type = %q", cfg.LookupType())
	}
	want := []string{"a.com", "b.com", "extra.com", "s1.com", "s2.com", "last.com"}
	if !reflect.DeepEqual(cfg.Targets, want) {
		t.Errorf("targets = %v, want %v", cfg.Targets, want)
	}
}

func TestParseArgsStdinAsFile(t *testing.T) {
	cfg, err := parseArgs([]string{"-o", "json", "--" + fakeFlag, "-"}, strings.NewReader("x.com\ny.com\n"), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"x.com", "y.com"}; !reflect.DeepEqual(cfg.Targets, want) {
		t.Errorf("targets = %v, want %v", cfg.Targets, want)
	}
	if cfg.Output != outputJSON {
		t.Errorf("output = %q", cfg.Output)
	}
}

func TestParseArgsInterspersedAndOptions(t *testing.T) {
	old := validateTarget
	validateTarget = func(string) error { return nil } // allow "-c.com" after "--"
	t.Cleanup(func() { validateTarget = old })
	cfg, err := parseArgs([]string{"a.com", "--output", "text", "b.com", "--lookup", fakeFlag,
		"--server", "1.1.1.1", "--timeout", "3s", "--concurrency", "2", "--", "-c.com"},
		strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.com", "b.com", "-c.com"}; !reflect.DeepEqual(cfg.Targets, want) {
		t.Errorf("targets = %v, want %v", cfg.Targets, want)
	}
	if cfg.Opts != (lookup.Options{Server: "1.1.1.1", Timeout: 3 * time.Second}) {
		t.Errorf("opts = %+v", cfg.Opts)
	}
	if cfg.Concurrency != 2 || cfg.Output != outputText || cfg.LookupType() != fakeName {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestParseArgsLookupByProviderName(t *testing.T) {
	cfg, err := parseArgs([]string{"--lookup", strings.ToLower(fakeName), "a.com"}, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LookupType() != fakeName {
		t.Errorf("lookup type = %q", cfg.LookupType())
	}
}

func TestParseArgsInvalidTargetsSkipped(t *testing.T) {
	withValidator(t)
	path := writeFile(t, "good.com\n# c\nbad1.com\n\nok.com\nbad2.com\n")
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{"--" + fakeFlag, path, "bad3.com", "fine.com"}, strings.NewReader(""), &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"good.com", "ok.com", "fine.com"}; !reflect.DeepEqual(cfg.Targets, want) {
		t.Errorf("targets = %v, want %v", cfg.Targets, want)
	}
	msg := stderr.String()
	for _, want := range []string{path + ":3:", `"bad1.com"`, path + ":6:", `"bad2.com"`, "argument 1:", `"bad3.com"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("stderr missing %q:\n%s", want, msg)
		}
	}
}

func TestParseArgsUsageErrors(t *testing.T) {
	path := writeFile(t, "a.com\n")
	cases := map[string][]string{
		"bad qtype":                 {"-t", "NOPE", "a.com"},
		"sdig option, other lookup": {"--lookup", fakeFlag, "--dnssec", "a.com"},
		"qtype, other lookup":       {"-t", "MX", "--" + fakeFlag, path},
		"headless without targets":  {"-o", "json", "--lookup", fakeFlag},
		"bad output":                {"-o", "xml", "--lookup", fakeFlag, "a.com"},
		"unknown lookup":            {"--lookup", "nope", "a.com"},
		"bad concurrency":           {"--concurrency", "0", "a.com"},
		"unknown flag":              {"--bogus"},
		"conflicting lookup":        {"--" + fakeFlag, path, "--lookup", "zz-other"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseArgs(args, strings.NewReader(""), &bytes.Buffer{})
			if !errors.Is(err, errUsage) {
				t.Errorf("err = %v, want usage error", err)
			}
		})
	}
}

func TestParseArgsMissingFile(t *testing.T) {
	_, err := parseArgs([]string{"--" + fakeFlag, filepath.Join(t.TempDir(), "missing.txt")}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil || errors.Is(err, errUsage) {
		t.Errorf("err = %v, want file error", err)
	}
}

func TestHelp(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseArgs([]string{"--help"}, strings.NewReader(""), &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"Usage:", "Examples:", "--output", "--" + fakeFlag, "duration_ms"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help missing %q", want)
		}
	}
	if code := run([]string{"-h"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Errorf("exit code = %d", code)
	}
}

func TestVersion(t *testing.T) {
	var stdout bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.HasPrefix(stdout.String(), "dlookup ") {
		t.Errorf("stdout = %q", stdout.String())
	}

	old := version
	version = "v1.2.3"
	t.Cleanup(func() { version = old })
	stdout.Reset()
	run([]string{"--version"}, strings.NewReader(""), &stdout, &bytes.Buffer{})
	if got := stdout.String(); got != "dlookup v1.2.3\n" {
		t.Errorf("stdout = %q", got)
	}
}

func TestRunUsageErrorExitCode(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"-o", "json", "--norecurse"}, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}
