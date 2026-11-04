package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"dlookup/lookup"
)

func TestRunHeadlessJSONOrder(t *testing.T) {
	targets := []string{"slow1.com", "fast.com", "fail.com", "slow2.com", "z.com"}
	var out bytes.Buffer
	failed, err := runHeadless(context.Background(), &out, fake, targets, lookup.Options{Server: "9.9.9.9"}, outputJSON, 3)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	var results []headlessResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	if len(results) != len(targets) {
		t.Fatalf("got %d results", len(results))
	}
	for i, r := range results {
		if r.Target != targets[i] || r.Lookup != fakeName {
			t.Errorf("result %d = %+v, want target %s", i, r, targets[i])
		}
		if (r.Error != "") != strings.Contains(r.Target, "fail") {
			t.Errorf("result %d error = %q", i, r.Error)
		}
	}
	if results[0].Output != "result for slow1.com" || results[0].DurationMS < 40 {
		t.Errorf("result 0 = %+v", results[0])
	}
	// Raw keys match the documented schema.
	var raw []map[string]any
	_ = json.Unmarshal(out.Bytes(), &raw)
	for _, k := range []string{"target", "lookup", "output", "error", "duration_ms"} {
		if _, ok := raw[0][k]; !ok {
			t.Errorf("missing JSON key %q", k)
		}
	}
	if fake.lastOpts.Server != "9.9.9.9" {
		t.Errorf("opts not passed: %+v", fake.lastOpts)
	}
}

func TestRunHeadlessText(t *testing.T) {
	var out bytes.Buffer
	failed, err := runHeadless(context.Background(), &out, fake, []string{"slow.com", "a.com", "fail.com"}, lookup.Options{}, outputText, 8)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Errorf("failed = %d", failed)
	}
	s := out.String()
	i1 := strings.Index(s, "=== slow.com ["+fakeName+"]")
	i2 := strings.Index(s, "=== a.com [")
	i3 := strings.Index(s, "=== fail.com [")
	if i1 < 0 || i2 < i1 || i3 < i2 {
		t.Errorf("headers missing or out of order:\n%s", s)
	}
	if !strings.Contains(s, "result for a.com\n") || !strings.Contains(s, "ERROR: lookup of fail.com failed") {
		t.Errorf("unexpected text output:\n%s", s)
	}
}

func TestRunHeadlessConcurrencyBound(t *testing.T) {
	fake.resetStats()
	targets := make([]string, 10)
	for i := range targets {
		targets[i] = "slow" + string(rune('a'+i)) + ".com"
	}
	if _, err := runHeadless(context.Background(), &bytes.Buffer{}, fake, targets, lookup.Options{}, outputText, 2); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.maxFlight > 2 || fake.maxFlight < 1 {
		t.Errorf("max in flight = %d, want <= 2", fake.maxFlight)
	}
}

func TestRunHeadlessCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failed, err := runHeadless(ctx, &bytes.Buffer{}, fake, []string{"slow1.com", "slow2.com", "slow3.com"}, lookup.Options{}, outputJSON, 1)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 3 {
		t.Errorf("failed = %d, want 3", failed)
	}
}

func TestRunHeadlessExitCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-o", "json", "--lookup", fakeFlag, "a.com", "b.com"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Errorf("exit code = %d, stderr: %s", code, stderr.String())
	}
	var results []headlessResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil || len(results) != 2 {
		t.Errorf("bad output (%v): %s", err, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := run([]string{"--output", "text", "--lookup", fakeFlag, "a.com", "fail.com"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "1 of 2 lookups failed") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
