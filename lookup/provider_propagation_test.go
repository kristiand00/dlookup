package lookup

import (
	"context"
	"testing"
)

func TestPropagation(t *testing.T) {
	w := newWorld(t, nil, nil, nil)
	fresh := newFake(t, nil, "example.test. 250 IN A 192.0.2.10")
	stale := newFake(t, nil, "example.test. 120 IN A 192.0.2.99")
	broken := newFake(t, nil)
	broken.set(func(f *fakeDNS) { f.refuse = true })
	old := PropagationResolvers
	PropagationResolvers = []PublicResolver{
		{"Fresh", "Test (A)", fresh.addr},
		{"Stale", "Test (B)", stale.addr},
		{"Broken", "Test (C)", broken.addr},
	}
	t.Cleanup(func() { PropagationResolvers = old })

	out, err := (&PropagationProvider{}).Execute(context.Background(), "example.test", w.opts)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out,
		"Propagation of example.test A (4 public resolvers)",
		"✓ 2/2 nameservers agree: 192.0.2.10 (TTL 300)",
		"Fresh (127.0.0.1:",
		"192.0.2.10  250/300  matches authoritative",
		"192.0.2.99  120/300  stale / different",
		"REFUSED",
		"error",
		"--server",
		"2 of 4 resolvers return the authoritative answer; 1 differ",
		"3 ok, 1 warning, 1 problem",
	)

	// Other types and NXDOMAIN agree.
	out, err = (&PropagationProvider{}).Execute(context.Background(), "nope.example.test", Options{Server: w.resolver.addr, Timeout: w.opts.Timeout, QType: "aaaa"})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "Propagation of nope.example.test AAAA", "NXDOMAIN")

	if _, err := (&PropagationProvider{}).Execute(context.Background(), "example.test", Options{QType: "BOGUS"}); err == nil {
		t.Error("unknown qtype accepted")
	}
}
