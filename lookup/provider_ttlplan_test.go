package lookup

import (
	"context"
	"testing"
	"time"
)

func TestTTLPlan(t *testing.T) {
	fixedNow(t, time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC))
	child := append(append([]string(nil), childRecords...),
		"www.example.test. 3600 IN CNAME example.test.",
		"mail.example.test. 86400 IN A 192.0.2.25",
		"mail.example.test. 86400 IN A 192.0.2.26",
		"example.test. 300 IN MX 10 mail.example.test.",
		`_dmarc.example.test. 60 IN TXT "v=DMARC1; p=none"`,
	)
	w := newWorld(t, nil, child, child)
	out, err := (&TTLPlanProvider{}).Execute(context.Background(), "example.test", w.opts)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out,
		"TTL plan for example.test (TTLs from ns1.example.test (198.51.100.1))",
		"86400    1d         A      mail.example.test.                   2",
		"3600     1h         CNAME  www.example.test.                    1",
		"60       1m         TXT    _dmarc.example.test.",
		"Max TTL:          86400 (1d) — mail.example.test. A",
		"Parent NS TTL:    86400 (1d) at test",
		"Negative TTL:     600 (10m)",
		"1. Lower the TTL of these 4 RRsets to 300 now:",
		"mail.example.test.                   A      86400 → 300",
		"Earliest safe switch: 2026-11-13 12:00 UTC",
		"keep the old provider serving the zone for at least 1d",
		"! 4 of 8 RRsets have TTL > 300",
	)
	mustNotContain(t, out, "SOA    3600 → 300")

	low := []string{
		"example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300",
		"example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN NS ns2.example.net.",
		"ns1.example.test. 300 IN A 198.51.100.1",
	}
	w = newWorld(t, nil, low, low)
	out, err = (&TTLPlanProvider{}).Execute(context.Background(), "example.test", w.opts)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "All TTLs are already at most 300s", "✓ all 3 RRsets have TTL ≤ 300: ready to switch")
}
