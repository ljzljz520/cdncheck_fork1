package cdncheck

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCDNCheckValid tests that IP addresses and domain suffixes match their expected CDN/WAF providers.
func TestCDNCheckValid(t *testing.T) {
	client := New()

	found, provider, itemType, err := client.Check(net.ParseIP("2400:cb00::1"))
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct item type")
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "Could not check cloudlfare ip blacklist")

	found, provider, itemType, err = client.Check(net.ParseIP("173.245.48.12"))
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct item type")
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "Could not check cloudlfare ip blacklist")

	found, _, _, err = client.Check(net.ParseIP("::1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.False(t, found, "Localhost IP found in blacklist")

	found, _, _, err = client.Check(net.ParseIP("127.0.0.1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.False(t, found, "Localhost IP found in blacklist")

	found, provider, itemType, err = client.Check(net.ParseIP("49.229.94.1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "could not match huawei cdn cidr")
	require.Equal(t, "huawei", provider, "could not get correct provider")
	require.Equal(t, "cdn", itemType, "could not get correct item type")

	// Aliyun CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.25.68.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match aliyun cdn cidr")
	require.Equal(t, "aliyun", provider)
	require.Equal(t, "cdn", itemType)

	// Wangsu CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.71.150.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match wangsu cdn cidr")
	require.Equal(t, "wangsu", provider)
	require.Equal(t, "cdn", itemType)

	// Tencent Cloud CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.56.98.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match tencent cdn cidr")
	require.Equal(t, "tencent", provider)
	require.Equal(t, "cdn", itemType)

	// F5 Distributed Cloud CDN / WAF
	found, provider, itemType, err = client.Check(net.ParseIP("84.54.61.10"))
	require.Nil(t, err)
	require.True(t, found, "could not match f5 cidr")
	require.Equal(t, "f5", provider)
	require.Contains(t, []string{"cdn", "waf"}, itemType)

	// Baidu Cloud CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.56.80.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match baidu cdn cidr")
	require.Equal(t, "baidu", provider)
	require.Equal(t, "cdn", itemType)

	// Baidu Domain Suffix
	found, provider, itemType, err = client.CheckSuffix("www.a.shifen.com")
	require.Nil(t, err)
	require.True(t, found, "could not match baidu shifen domain suffix")
	require.Equal(t, "baidu", provider)
	require.Equal(t, "waf", itemType)
}

func TestCheckGoogleCloudCustomerIPIsCloud(t *testing.T) {
	client := New()

	// A Compute Engine VM in a cloud.json range: Google Cloud, not the google CDN.
	found, provider, itemType, err := client.Check(net.ParseIP("34.67.190.20"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "could not match google cloud cidr")
	require.Equal(t, "google", provider, "could not get correct provider")
	require.Equal(t, "cloud", itemType, "a google cloud customer ip must not match as cdn")

	// A Google front end outside cloud.json stays in the google CDN.
	found, provider, itemType, err = client.Check(net.ParseIP("142.250.80.46"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "could not match google cdn cidr")
	require.Equal(t, "google", provider, "could not get correct provider")
	require.Equal(t, "cdn", itemType, "could not get correct item type")
}

// syntheticCompiledInput builds deterministic provider data exercising nested
// segments (CDN), identical segments shared by two providers (WAF) and a plain
// single-provider segment (Cloud).
func syntheticCompiledInput() InputCompiled {
	return InputCompiled{
		CDN: map[string][]string{
			"zeta-cdn":  {"192.0.2.0/24"},
			"alpha-cdn": {"192.0.2.128/25"},
		},
		WAF: map[string][]string{
			"waf-a": {"198.51.100.0/24"},
			"waf-b": {"198.51.100.0/24"},
		},
		Cloud: map[string][]string{
			"cloud-x": {"203.0.113.0/24"},
		},
	}
}

// TestProviderScraperNestedPrefixCandidates verifies that nested segments keep
// every attribution and that the longest prefix wins the stable adjudication.
func TestProviderScraperNestedPrefixCandidates(t *testing.T) {
	scraper := newProviderScraper(syntheticCompiledInput().CDN)

	// 192.0.2.130 is inside both the /25 (alpha-cdn) and the /24 (zeta-cdn).
	ip := net.ParseIP("192.0.2.130")
	candidates, err := scraper.Candidates(ip)
	require.NoError(t, err)
	require.Len(t, candidates, 2, "nested segments must retain both attributions")

	require.Equal(t, "alpha-cdn", candidates[0].Provider)
	require.Equal(t, "192.0.2.128/25", candidates[0].Prefix.String())
	require.Equal(t, 25, candidates[0].Prefix.Bits())
	require.Equal(t, "zeta-cdn", candidates[1].Provider)
	require.Equal(t, "192.0.2.0/24", candidates[1].Prefix.String())
	require.Equal(t, 24, candidates[1].Prefix.Bits())

	// the legacy single-result interface follows longest-prefix-first.
	matched, provider, err := scraper.Match(ip)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "alpha-cdn", provider)

	// an address covered only by the outer segment returns that one.
	outerOnly := net.ParseIP("192.0.2.10")
	candidates, err = scraper.Candidates(outerOnly)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "zeta-cdn", candidates[0].Provider)
	require.Equal(t, "192.0.2.0/24", candidates[0].Prefix.String())

	matched, provider, err = scraper.Match(outerOnly)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "zeta-cdn", provider)

	// an address outside every segment has no candidate.
	candidates, err = scraper.Candidates(net.ParseIP("10.0.0.1"))
	require.NoError(t, err)
	require.Empty(t, candidates)
	matched, _, err = scraper.Match(net.ParseIP("10.0.0.1"))
	require.NoError(t, err)
	require.False(t, matched)
}

// TestProviderScraperIdenticalPrefixCandidates verifies that an identical
// segment shared by several providers keeps every identifier and that ties are
// broken by the provider identifier.
func TestProviderScraperIdenticalPrefixCandidates(t *testing.T) {
	scraper := newProviderScraper(syntheticCompiledInput().WAF)

	candidates, err := scraper.Candidates(net.ParseIP("198.51.100.7"))
	require.NoError(t, err)
	require.Len(t, candidates, 2, "identical segment must retain every provider")
	require.Equal(t, 24, candidates[0].Prefix.Bits())
	require.Equal(t, 24, candidates[1].Prefix.Bits())
	require.Equal(t, "198.51.100.0/24", candidates[0].Prefix.String())
	require.Equal(t, "198.51.100.0/24", candidates[1].Prefix.String())
	// equal prefix length: stable ordering by provider identifier.
	require.Equal(t, "waf-a", candidates[0].Provider)
	require.Equal(t, "waf-b", candidates[1].Provider)

	matched, provider, err := scraper.Match(net.ParseIP("198.51.100.7"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "waf-a", provider, "tie must be broken by the provider identifier")
}

// TestProviderScraperRepeatedQueriesAreStable verifies repeated lookups return
// byte-identical candidate sets instead of depending on map traversal order.
func TestProviderScraperRepeatedQueriesAreStable(t *testing.T) {
	scraper := newProviderScraper(syntheticCompiledInput().CDN)
	ip := net.ParseIP("192.0.2.130")

	first, err := scraper.Candidates(ip)
	require.NoError(t, err)
	require.Len(t, first, 2)

	for i := 0; i < 50; i++ {
		got, err := scraper.Candidates(ip)
		require.NoError(t, err)
		require.Equal(t, first, got, "candidate set must be stable across queries")

		matched, provider, err := scraper.Match(ip)
		require.NoError(t, err)
		require.True(t, matched)
		require.Equal(t, first[0].Provider, provider)
	}
}

// TestProviderScraperConcurrentReads verifies the read-only index is safe for
// concurrent access and always yields the same adjudication.
func TestProviderScraperConcurrentReads(t *testing.T) {
	data := syntheticCompiledInput()
	cdnScraper := newProviderScraper(data.CDN)
	wafScraper := newProviderScraper(data.WAF)

	nestedIP := net.ParseIP("192.0.2.130")
	sharedIP := net.ParseIP("198.51.100.7")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			cdnCandidates, err := cdnScraper.Candidates(nestedIP)
			assert.NoError(t, err)
			assert.Len(t, cdnCandidates, 2)
			if len(cdnCandidates) == 2 {
				assert.Equal(t, "alpha-cdn", cdnCandidates[0].Provider)
				assert.Equal(t, "zeta-cdn", cdnCandidates[1].Provider)
			}
			matched, provider, err := cdnScraper.Match(nestedIP)
			assert.NoError(t, err)
			assert.True(t, matched)
			assert.Equal(t, "alpha-cdn", provider)

			wafCandidates, err := wafScraper.Candidates(sharedIP)
			assert.NoError(t, err)
			assert.Len(t, wafCandidates, 2)
			matched, provider, err = wafScraper.Match(sharedIP)
			assert.NoError(t, err)
			assert.True(t, matched)
			assert.Equal(t, "waf-a", provider)
		}(i)
	}
	wg.Wait()
}

// TestCheckCandidatesAndCategoryPriority verifies the complete candidate query
// and that CDN keeps precedence over WAF and Cloud when ranges overlap.
func TestCheckCandidatesAndCategoryPriority(t *testing.T) {
	data := syntheticCompiledInput()
	// the same segment is attributed in all three categories on purpose.
	data.WAF["shared-waf"] = []string{"192.0.2.0/24"}
	data.Cloud["shared-cloud"] = []string{"192.0.2.0/24"}

	client, err := NewWithData(data, 1, []string{"1.1.1.1:53"})
	require.NoError(t, err)

	ip := net.ParseIP("192.0.2.130")

	candidates, itemType, err := client.CheckCandidates(ip)
	require.NoError(t, err)
	require.Equal(t, "cdn", itemType, "CDN must keep precedence over WAF and Cloud")
	require.Len(t, candidates, 2)
	require.Equal(t, "alpha-cdn", candidates[0].Provider)
	require.Equal(t, "192.0.2.128/25", candidates[0].Prefix.String())
	require.Equal(t, "zeta-cdn", candidates[1].Provider)

	// the legacy generic interface stays stable and keeps the same priority.
	matched, provider, gotType, err := client.Check(ip)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "alpha-cdn", provider)
	require.Equal(t, "cdn", gotType)

	// category specific interfaces still expose the other attributions.
	matched, provider, err = client.CheckWAF(ip)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "shared-waf", provider)

	matched, provider, err = client.CheckCloud(ip)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "shared-cloud", provider)

	// a cloud-only address is reported with the cloud category.
	candidates, itemType, err = client.CheckCandidates(net.ParseIP("203.0.113.5"))
	require.NoError(t, err)
	require.Equal(t, "cloud", itemType)
	require.Len(t, candidates, 1)
	require.Equal(t, "cloud-x", candidates[0].Provider)
	require.Equal(t, "203.0.113.0/24", candidates[0].Prefix.String())

	// unknown addresses produce an empty result without error.
	candidates, itemType, err = client.CheckCandidates(net.ParseIP("10.0.0.1"))
	require.NoError(t, err)
	require.Nil(t, candidates)
	require.Equal(t, "", itemType)

	// invalid addresses surface the parse error.
	candidates, itemType, err = client.CheckCandidates(nil)
	require.Error(t, err)
	require.Nil(t, candidates)
	require.Equal(t, "", itemType)
}
