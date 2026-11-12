package lookup

import (
	"context"
	"testing"
)

func TestTakeoverMatch(t *testing.T) {
	for host, want := range map[string]string{
		"assets.s3.amazonaws.com.":                 "AWS S3",
		"bucket.s3-eu-west-1.amazonaws.com":        "AWS S3",
		"site.s3-website-us-east-1.amazonaws.com.": "AWS S3",
		"d111111abcdef8.cloudfront.net.":           "AWS CloudFront",
		"myapp.azurewebsites.net":                  "Azure App Service",
		"x.cloudapp.net":                           "Azure Cloud Services",
		"x.trafficmanager.net":                     "Azure Traffic Manager",
		"acct.blob.core.windows.net":               "Azure Blob Storage",
		"app.herokuapp.com":                        "Heroku",
		"abc.herokudns.com.":                       "Heroku",
		"org.github.io.":                           "GitHub Pages",
		"blog.ghost.io":                            "Ghost",
		"shop.myshopify.com":                       "Shopify",
		"help.zendesk.com":                         "Zendesk",
		"x.global.fastly.net":                      "Fastly",
		"site.netlify.app":                         "Netlify",
		"cname.vercel-dns.com.":                    "Vercel",
		"x.vercel.app":                             "Vercel",
		"live-x.pantheonsite.io":                   "Pantheon",
		"proj.readthedocs.io":                      "Read the Docs",
		"x.surge.sh":                               "Surge.sh",
		"x.bitbucket.io":                           "Bitbucket",
		"x.wpengine.com":                           "WP Engine",
		"x.unbouncepages.com":                      "Unbounce",
		"github.com.":                              "",
		"example.com":                              "",
		"notgithub.io.example.com":                 "",
		"s3.amazonaws.com.evil.example":            "",
		"autodiscover.outlook.com":                 "",
	} {
		if got := takeoverMatch(host); got != want {
			t.Errorf("takeoverMatch(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestTakeoverExecute(t *testing.T) {
	resolver := newFake(t, nil,
		"example.test. 300 IN SOA ns1.example.test. h.example.test. 1 2 3 4 300",
		"example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN A 192.0.2.10",
		"ns1.example.test. 300 IN A 192.0.2.53",
		"www.example.test. 300 IN CNAME example.test.",
		"blog.example.test. 300 IN CNAME oldblog.s3.amazonaws.com.",
		"shop.example.test. 300 IN CNAME shop.myshopify.com.",
		"shop.myshopify.com. 300 IN A 192.0.2.20",
		"api.example.test. 300 IN CNAME gone.example.net.",
		"dev.example.test. 300 IN NS ns1.deleted-dns.example.net.",
		"dev.example.test. 300 IN NS ns1.example.test.",
		"docs.example.test. 300 IN CNAME docs.example.net.",
		"docs.example.net. 300 IN TXT \"no address here\"",
	)
	resolver.set(func(f *fakeDNS) { f.rcode["staging.example.test."] = 2 }) // SERVFAIL
	out, err := (&TakeoverProvider{}).Execute(context.Background(), "example.test", testOpts(resolver))
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out,
		"blog.example.test → oldblog.s3.amazonaws.com. (NXDOMAIN) [AWS S3]",
		"✓ www.example.test: CNAME target example.test. resolves",
		"✗ blog.example.test: possible subdomain takeover — AWS S3 target oldblog.s3.amazonaws.com. does not resolve (NXDOMAIN)",
		"! shop.example.test: points to Shopify (shop.myshopify.com.) — check the resource still exists",
		"✗ api.example.test: dangling CNAME — gone.example.net. does not resolve (NXDOMAIN)",
		"✗ docs.example.test: dangling CNAME — docs.example.net. does not resolve (no address)",
		"✗ dev.example.test: dangling NS delegation — ns1.deleted-dns.example.net. does not exist",
		"! staging.example.test: delegated but its nameservers answer SERVFAIL",
		"✓ example.test: all 1 nameservers exist",
	)
}

func TestTakeoverWildcard(t *testing.T) {
	resolver := newFake(t, nil,
		"example.test. 300 IN SOA ns1.example.test. h.example.test. 1 2 3 4 300",
		"example.test. 300 IN A 192.0.2.10",
		"dlookup-takeover-probe-5c1e.example.test. 300 IN CNAME site.example.test.",
		"www.example.test. 300 IN CNAME site.example.test.",
		"mail.example.test. 300 IN CNAME site.example.test.",
		"site.example.test. 300 IN A 192.0.2.10",
	)
	out, err := (&TakeoverProvider{}).Execute(context.Background(), "example.test", testOpts(resolver))
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "*.example.test → site.example.test. (resolves) — wildcard")
	mustNotContain(t, out, "www.example.test →", "mail.example.test →")
}
