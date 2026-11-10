package runner

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

func TestRunWithThreadsReturnsEveryInput(t *testing.T) {
	inputs := []string{
		"192.0.2.1",
		"192.0.2.2",
		"192.0.2.3",
		"192.0.2.4",
		"198.51.100.1",
		"198.51.100.2",
		"203.0.113.1",
		"203.0.113.2",
	}

	var mu sync.Mutex
	got := map[string]int{}
	runner := NewRunner(&Options{
		Inputs:  inputs,
		Threads: 4,
		Exclude: true,
		OnResult: func(result Output) {
			mu.Lock()
			got[result.Input]++
			mu.Unlock()
		},
	})

	require.NoError(t, runner.Run())
	require.Len(t, got, len(inputs))
	for _, input := range inputs {
		require.Equal(t, 1, got[input])
	}
}

// syntheticRunnerInput overlaps two CDN providers on nested segments and two
// WAF providers on an identical segment, so candidate-set decisions can be
// exercised deterministically without network access.
func syntheticRunnerInput() cdncheck.InputCompiled {
	return cdncheck.InputCompiled{
		CDN: map[string][]string{
			"zeta-cdn":  {"192.0.2.0/24"},
			"alpha-cdn": {"192.0.2.128/25"},
		},
		WAF: map[string][]string{
			"waf-a": {"198.51.100.0/24"},
			"waf-b": {"198.51.100.0/24"},
		},
	}
}

func newSyntheticRunner(t *testing.T, options *Options) *Runner {
	t.Helper()
	runner := NewRunner(options)
	client, err := cdncheck.NewWithData(syntheticRunnerInput(), 1, []string{"1.1.1.1:53"})
	require.NoError(t, err)
	runner.cdnclient = client
	return runner
}

func runAndCollect(t *testing.T, options *Options, inputs []string) []Output {
	t.Helper()
	options.Inputs = inputs
	var mu sync.Mutex
	results := make([]Output, 0)
	options.OnResult = func(result Output) {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}
	runner := newSyntheticRunner(t, options)
	require.NoError(t, runner.Run())
	return results
}

// TestRunnerCandidateSetMatchingAndFiltering verifies matchers and filters
// decide on the full candidate set, including attributions that lose the
// longest-prefix adjudication, and that combinations keep their precedence.
func TestRunnerCandidateSetMatchingAndFiltering(t *testing.T) {
	const nestedCDNIP = "192.0.2.130"  // alpha-cdn /25 wins, zeta-cdn /24 also matches
	const sharedWAFIP = "198.51.100.7" // waf-a and waf-b share the same /24

	tests := []struct {
		name    string
		options *Options
		input   string
		want    bool
	}{
		{name: "no matcher keeps the item", options: &Options{}, input: nestedCDNIP, want: true},
		{name: "matcher on the winning provider keeps", options: &Options{MatchCdn: goflags.StringSlice{"alpha-cdn"}}, input: nestedCDNIP, want: true},
		{name: "matcher on a secondary candidate keeps", options: &Options{MatchCdn: goflags.StringSlice{"zeta-cdn"}}, input: nestedCDNIP, want: true},
		{name: "matcher on an unknown provider drops", options: &Options{MatchCdn: goflags.StringSlice{"nobody-cdn"}}, input: nestedCDNIP, want: false},
		{name: "filter on the winning provider drops", options: &Options{FilterCdn: goflags.StringSlice{"alpha-cdn"}}, input: nestedCDNIP, want: false},
		{name: "filter on a secondary candidate drops", options: &Options{FilterCdn: goflags.StringSlice{"zeta-cdn"}}, input: nestedCDNIP, want: false},
		{name: "filter on an unknown provider keeps", options: &Options{FilterCdn: goflags.StringSlice{"nobody-cdn"}}, input: nestedCDNIP, want: true},
		{name: "filter takes precedence over matcher", options: &Options{MatchCdn: goflags.StringSlice{"alpha-cdn"}, FilterCdn: goflags.StringSlice{"zeta-cdn"}}, input: nestedCDNIP, want: false},
		{name: "matcher plus unrelated filter keeps", options: &Options{MatchCdn: goflags.StringSlice{"zeta-cdn"}, FilterCdn: goflags.StringSlice{"nobody-cdn"}}, input: nestedCDNIP, want: true},
		{name: "waf matcher on secondary identifier keeps", options: &Options{MatchWaf: goflags.StringSlice{"waf-b"}}, input: sharedWAFIP, want: true},
		{name: "waf filter on primary identifier drops", options: &Options{FilterWaf: goflags.StringSlice{"waf-a"}}, input: sharedWAFIP, want: false},
		{name: "cross-category matcher does not match cdn item", options: &Options{MatchWaf: goflags.StringSlice{"alpha-cdn"}}, input: nestedCDNIP, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := runAndCollect(t, tc.options, []string{tc.input})
			if tc.want {
				require.Len(t, results, 1)
			} else {
				require.Empty(t, results)
			}
		})
	}
}

// TestRunnerStructuredOutputRetainsCandidates verifies the JSON output keeps
// the adjudication basis: every provider with the segment that matched.
func TestRunnerStructuredOutputRetainsCandidates(t *testing.T) {
	results := runAndCollect(t, &Options{}, []string{"192.0.2.130"})
	require.Len(t, results, 1)

	result := results[0]
	require.True(t, result.Cdn)
	require.Equal(t, "alpha-cdn", result.CdnName)
	require.Len(t, result.Matches, 2)
	require.Equal(t, "alpha-cdn", result.Matches[0].Provider)
	require.Equal(t, "192.0.2.128/25", result.Matches[0].Prefix.String())
	require.Equal(t, "zeta-cdn", result.Matches[1].Provider)
	require.Equal(t, "192.0.2.0/24", result.Matches[1].Prefix.String())

	raw, err := json.Marshal(result)
	require.NoError(t, err)
	text := string(raw)
	require.Contains(t, text, `"matches"`)
	require.Contains(t, text, `"provider":"alpha-cdn"`)
	require.Contains(t, text, `"prefix":"192.0.2.128/25"`)
	require.Contains(t, text, `"provider":"zeta-cdn"`)
	require.Contains(t, text, `"prefix":"192.0.2.0/24"`)
}

// TestRunnerExcludeAndCategoryFlags verifies exclude mode and the category
// selection flags keep their established behavior with candidate based input.
func TestRunnerExcludeAndCategoryFlags(t *testing.T) {
	// exclude keeps only unmatched inputs.
	results := runAndCollect(t, &Options{Exclude: true}, []string{"192.0.2.130", "10.0.0.1"})
	require.Len(t, results, 1)
	require.Equal(t, "10.0.0.1", results[0].Input)

	// cdn flag selects the cdn item, waf flag does not.
	results = runAndCollect(t, &Options{Cdn: true}, []string{"192.0.2.130"})
	require.Len(t, results, 1)
	require.Equal(t, "cdn", results[0].itemType)

	results = runAndCollect(t, &Options{Waf: true}, []string{"192.0.2.130"})
	require.Empty(t, results)

	// waf flag selects the identical-segment waf item.
	results = runAndCollect(t, &Options{Waf: true}, []string{"198.51.100.7"})
	require.Len(t, results, 1)
	require.Equal(t, "waf", results[0].itemType)
	require.Equal(t, "waf-a", results[0].WafName)
	require.Len(t, results[0].Matches, 2)
}

// TestRunnerRepeatedInputsAreStable verifies multiple queries over the same IP
// produce identical adjudications and candidate sets.
func TestRunnerRepeatedInputsAreStable(t *testing.T) {
	inputs := []string{"192.0.2.130", "192.0.2.130", "192.0.2.130", "198.51.100.7", "198.51.100.7"}
	results := runAndCollect(t, &Options{Threads: 4}, inputs)
	require.Len(t, results, len(inputs))

	for _, result := range results {
		switch result.Input {
		case "192.0.2.130":
			require.Equal(t, "alpha-cdn", result.CdnName)
			require.Len(t, result.Matches, 2)
			require.Equal(t, "192.0.2.128/25", result.Matches[0].Prefix.String())
		case "198.51.100.7":
			require.Equal(t, "waf-a", result.WafName)
			require.Len(t, result.Matches, 2)
		default:
			t.Fatalf("unexpected input %s", result.Input)
		}
	}
}
