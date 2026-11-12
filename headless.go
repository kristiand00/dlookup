package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"dlookup/lookup"
)

// headlessResult is the result of one lookup; also the JSON output schema.
type headlessResult struct {
	Target     string `json:"target"`
	Lookup     string `json:"lookup"`
	Output     string `json:"output"`
	Error      string `json:"error"`
	DurationMS int64  `json:"duration_ms"`
}

// runHeadless runs provider on every target with at most concurrency lookups in
// flight, writing results to w in input order as soon as each is available.
// format is outputText or outputJSON. Returns the number of failed lookups and
// any error writing to w.
func runHeadless(ctx context.Context, w io.Writer, provider lookup.LookupProvider, targets []string, opts lookup.Options, format string, concurrency int) (failed int, err error) {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]headlessResult, len(targets))
	done := make([]chan struct{}, len(targets))
	for i := range done {
		done[i] = make(chan struct{})
	}

	// Dispatch in input order so earlier targets tend to finish first.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem := make(chan struct{}, concurrency)
		for i, target := range targets {
			res := headlessResult{Target: target, Lookup: lookupLabel(provider.Name(), target, opts)}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				res.Error = ctx.Err().Error()
				results[i] = res
				close(done[i])
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				defer close(done[i])
				start := time.Now()
				out, lerr := provider.Execute(ctx, target, opts)
				res.DurationMS = time.Since(start).Milliseconds()
				res.Output = out
				if lerr != nil {
					res.Error = lerr.Error()
				}
				results[i] = res
			}()
		}
	}()
	// Ensure all goroutines finish before returning, even on write errors.
	defer wg.Wait()

	var writeErr error
	write := func(s string) {
		if writeErr == nil {
			_, writeErr = io.WriteString(w, s)
		}
	}

	if format == outputJSON {
		write("[\n")
	}
	for i := range targets {
		<-done[i]
		res := results[i]
		if res.Error != "" {
			failed++
		}
		switch format {
		case outputJSON:
			b, merr := json.MarshalIndent(res, "  ", "  ")
			if merr != nil {
				return failed, merr
			}
			sep := ",\n"
			if i == len(targets)-1 {
				sep = "\n"
			}
			write("  " + string(b) + sep)
		default:
			write(formatTextResult(res))
		}
	}
	if format == outputJSON {
		write("]\n")
	}
	return failed, writeErr
}

func formatTextResult(r headlessResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== %s [%s] (%dms) ===\n", r.Target, r.Lookup, r.DurationMS)
	if out := strings.TrimRight(r.Output, "\n"); out != "" {
		b.WriteString(out)
		b.WriteString("\n")
	}
	if r.Error != "" {
		fmt.Fprintf(&b, "ERROR: %s\n", r.Error)
	}
	b.WriteString("\n")
	return b.String()
}
