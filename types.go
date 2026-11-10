package cdncheck

import (
	"net"
	"net/netip"
	"sort"

	"github.com/gaissmai/bart"
)

// InputCompiled contains a compiled list of input structure
type InputCompiled struct {
	// CDN contains a list of ranges for CDN cidrs
	CDN map[string][]string `yaml:"cdn,omitempty" json:"cdn,omitempty"`
	// WAF contains a list of ranges for WAF cidrs
	WAF map[string][]string `yaml:"waf,omitempty" json:"waf,omitempty"`
	// Cloud contains a list of ranges for Cloud cidrs
	Cloud map[string][]string `yaml:"cloud,omitempty" json:"cloud,omitempty"`
	// Common contains a list of suffixes for major sources
	Common map[string][]string `yaml:"common,omitempty" json:"common,omitempty"`
}

// PrefixCandidate describes a single provider attribution for an IP address.
// It retains both the provider identifier and the exact network segment
// (CIDR prefix) that matched, so callers can see every attribution of an IP
// instead of only the first one encountered during map traversal.
type PrefixCandidate struct {
	// Provider is the identifier of the provider owning the prefix.
	Provider string `json:"provider" yaml:"provider"`
	// Prefix is the network segment that contains the queried IP.
	Prefix netip.Prefix `json:"prefix" yaml:"prefix"`
}

// providerScraper is a structure for scraping providers.
//
// All provider ranges of a category are merged into a single routing table.
// Every prefix maps to the identifiers of the providers owning that exact
// segment, which preserves attributions when providers share identical
// segments or when segments are nested.
type providerScraper struct {
	rangers *bart.Table[[]string]
}

// newProviderScraper returns a new provider scraper instance
func newProviderScraper(ranges map[string][]string) *providerScraper {
	scraper := &providerScraper{rangers: new(bart.Table[[]string])}

	for provider, items := range ranges {
		for _, cidr := range items {
			network, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			// Several providers may declare the very same segment: keep every
			// identifier on the prefix instead of overwriting it.
			scraper.rangers.Modify(network, func(existing []string, ok bool) ([]string, bool) {
				if !ok {
					return []string{provider}, false
				}
				for _, known := range existing {
					if known == provider {
						return existing, false
					}
				}
				return append(existing, provider), false
			})
		}
	}
	return scraper
}

// Candidates returns every provider/prefix attribution for ip within the
// category. The result is deterministic: longest matching prefix first, and
// for prefixes of equal length (identical segments shared by several
// providers) providers are sorted by their identifier.
func (p *providerScraper) Candidates(ip net.IP) ([]PrefixCandidate, error) {
	parsed, err := netip.ParseAddr(ip.String())
	if err != nil {
		return nil, err
	}

	// A host prefix (/32 for IPv4, /128 for IPv6) lets Supernets enumerate
	// every stored segment containing the address, from most to least specific.
	hostPrefix := netip.PrefixFrom(parsed, parsed.BitLen())

	candidates := make([]PrefixCandidate, 0)
	for prefix, providers := range p.rangers.Supernets(hostPrefix) {
		for _, provider := range providers {
			candidates = append(candidates, PrefixCandidate{Provider: provider, Prefix: prefix})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Prefix.Bits() != candidates[j].Prefix.Bits() {
			return candidates[i].Prefix.Bits() > candidates[j].Prefix.Bits()
		}
		return candidates[i].Provider < candidates[j].Provider
	})

	return candidates, nil
}

// Match returns true if the IP matches provided CIDR ranges.
//
// When several providers match, the result is stable: the provider of the
// longest matching prefix wins, ties (identical segments) are broken by the
// provider identifier. Use Candidates to retrieve the full attribution set.
func (p *providerScraper) Match(ip net.IP) (bool, string, error) {
	candidates, err := p.Candidates(ip)
	if err != nil {
		return false, "", err
	}
	if len(candidates) == 0 {
		return false, "", nil
	}
	return true, candidates[0].Provider, nil
}
