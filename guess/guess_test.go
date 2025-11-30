package guess

import (
	"testing"

	"github.com/codeGROOVE-dev/sociopath/profile"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"twitter.com", "https://twitter.com/user", "twitter.com/user"},
		{"x.com normalized to twitter.com", "https://x.com/user", "twitter.com/user"},
		{"http protocol", "http://twitter.com/user", "twitter.com/user"},
		{"trailing slash", "https://twitter.com/user/", "twitter.com/user"},
		{"www prefix", "https://www.twitter.com/user", "twitter.com/user"},
		{"uppercase", "https://Twitter.com/User", "twitter.com/user"},
		{"x.com with www", "https://www.x.com/user", "twitter.com/user"},
		{"linkedin", "https://linkedin.com/in/user", "linkedin.com/in/user"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeURL(tt.url)
			if got != tt.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestGenerateCandidates_SkipsKnownURLs(t *testing.T) {
	usernames := []string{"n4j"}

	// Simulate that we already fetched twitter.com/n4j
	knownURLs := map[string]bool{
		"twitter.com/n4j": true,
	}
	knownPlatforms := map[string]bool{}

	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms)

	// Check that no Twitter candidate was generated (because x.com normalizes to twitter.com)
	for _, c := range candidates {
		normalized := normalizeURL(c.url)
		if normalized == "twitter.com/n4j" {
			t.Errorf("generateCandidates should not include twitter.com/n4j when it's already in knownURLs, but got candidate: %s", c.url)
		}
	}
}

func TestGenerateCandidates_SkipsXcomWhenTwitterKnown(t *testing.T) {
	usernames := []string{"n4j"}

	// Simulate that we already fetched x.com/n4j (which normalizes to twitter.com/n4j)
	knownURLs := map[string]bool{
		normalizeURL("https://x.com/n4j"): true,
	}
	knownPlatforms := map[string]bool{}

	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms)

	// Check that no Twitter candidate was generated
	for _, c := range candidates {
		normalized := normalizeURL(c.url)
		if normalized == "twitter.com/n4j" {
			t.Errorf("generateCandidates should not include twitter candidate when x.com is already known, but got: %s", c.url)
		}
	}
}

func TestExtractUsernames(t *testing.T) {
	tests := []struct {
		name     string
		profiles []*profile.Profile
		want     []string
	}{
		{
			name: "extract from social platforms",
			profiles: []*profile.Profile{
				{Platform: "github", Username: "user1"},
				{Platform: "twitter", Username: "user2"},
			},
			want: []string{"user1", "user2"},
		},
		{
			name: "skip generic platform",
			profiles: []*profile.Profile{
				{Platform: "generic", Username: "should_skip"},
				{Platform: "github", Username: "keep_this"},
			},
			want: []string{"keep_this"},
		},
		{
			name: "deduplicate usernames",
			profiles: []*profile.Profile{
				{Platform: "github", Username: "duplicate"},
				{Platform: "twitter", Username: "duplicate"},
			},
			want: []string{"duplicate"},
		},
		{
			name: "skip short usernames",
			profiles: []*profile.Profile{
				{Platform: "github", Username: "ab"},
				{Platform: "github", Username: "validuser"},
			},
			want: []string{"validuser"},
		},
		{
			name: "skip invalid usernames",
			profiles: []*profile.Profile{
				{Platform: "github", Username: "user"},
				{Platform: "github", Username: "api"},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUsernames(tt.profiles)
			if len(got) != len(tt.want) {
				t.Errorf("extractUsernames() returned %d usernames, want %d\ngot: %v\nwant: %v", len(got), len(tt.want), got, tt.want)
				return
			}
			for i, want := range tt.want {
				if got[i] != want {
					t.Errorf("extractUsernames()[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}
