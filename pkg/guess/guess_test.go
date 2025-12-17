package guess

import (
	"slices"
	"testing"

	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
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

	vouchedPlatforms := map[string]bool{}
	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms, vouchedPlatforms, DefaultMaxCandidatesPerPlatform)

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
	vouchedPlatforms := map[string]bool{}
	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms, vouchedPlatforms, DefaultMaxCandidatesPerPlatform)

	// Check that no Twitter candidate was generated
	for _, c := range candidates {
		normalized := normalizeURL(c.url)
		if normalized == "twitter.com/n4j" {
			t.Errorf("generateCandidates should not include twitter candidate when x.com is already known, but got: %s", c.url)
		}
	}
}

func TestGenerateCandidates_LimitsPerPlatform(t *testing.T) {
	// Multiple usernames should still only generate max DefaultMaxCandidatesPerPlatform candidates per platform
	usernames := []string{"user1", "user2", "user3", "user4", "user5"}

	knownURLs := map[string]bool{}
	knownPlatforms := map[string]bool{}
	vouchedPlatforms := map[string]bool{}
	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms, vouchedPlatforms, DefaultMaxCandidatesPerPlatform)

	// Count candidates per platform
	platformCounts := make(map[string]int)
	for _, c := range candidates {
		platformCounts[c.platform]++
	}

	// Verify no platform has more than DefaultMaxCandidatesPerPlatform candidates
	for platform, count := range platformCounts {
		if count > DefaultMaxCandidatesPerPlatform {
			t.Errorf("platform %q has %d candidates, want at most %d", platform, count, DefaultMaxCandidatesPerPlatform)
		}
	}
}

func TestGenerateCandidates_PrioritizesQualityUsernames(t *testing.T) {
	// User with digits should be prioritized over short username
	usernames := []string{"joe", "tpope", "user123"}

	knownURLs := map[string]bool{}
	knownPlatforms := map[string]bool{}
	vouchedPlatforms := map[string]bool{}
	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms, vouchedPlatforms, DefaultMaxCandidatesPerPlatform)

	// Find the GitHub candidates (limited to DefaultMaxCandidatesPerPlatform)
	var githubUsernames []string
	for _, c := range candidates {
		if c.platform == "github" {
			githubUsernames = append(githubUsernames, c.username)
		}
	}

	// user123 should be included (has digits = higher quality)
	if !slices.Contains(githubUsernames, "user123") {
		t.Errorf("expected user123 to be prioritized in GitHub candidates, got: %v", githubUsernames)
	}
}

func TestIsValidUsernameForPlatform(t *testing.T) {
	tests := []struct {
		username string
		platform string
		want     bool
	}{
		// LinkedIn: 3-100 chars, alphanumeric and hyphens only
		{"tpope", "linkedin", true},
		{"tim-pope", "linkedin", true},
		{"ab", "linkedin", false},        // too short
		{"tpo.pe", "linkedin", false},    // has dot
		{"tim_pope", "linkedin", false},  // has underscore
		{"-tpope", "linkedin", false},    // starts with hyphen
		{"tpope-", "linkedin", false},    // ends with hyphen
		{"tim--pope", "linkedin", false}, // consecutive hyphens

		// Twitter: 4-15 chars, alphanumeric and underscores
		{"tpope", "twitter", true},
		{"tim_pope", "twitter", true},
		{"abc", "twitter", false},                 // too short (min 4)
		{"tpo.pe", "twitter", false},              // has dot
		{"tim-pope", "twitter", false},            // has hyphen
		{"verylongusername123", "twitter", false}, // too long (max 15)

		// GitHub: 1-39 chars, alphanumeric and hyphens
		{"tpope", "github", true},
		{"tim-pope", "github", true},
		{"a", "github", true},          // single char OK
		{"-tpope", "github", false},    // starts with hyphen
		{"tim--pope", "github", false}, // consecutive hyphens
		{"tim_pope", "github", false},  // has underscore

		// Instagram: 1-30 chars, alphanumeric, underscores, periods
		{"tpope", "instagram", true},
		{"tim.pope", "instagram", true},
		{"tim_pope", "instagram", true},
		{".tpope", "instagram", false},    // starts with period
		{"tpope.", "instagram", false},    // ends with period
		{"tim..pope", "instagram", false}, // consecutive periods
		{"tim-pope", "instagram", false},  // has hyphen

		// Reddit: 3-20 chars, alphanumeric, underscores, hyphens
		{"tpope", "reddit", true},
		{"tim_pope", "reddit", true},
		{"tim-pope", "reddit", true},
		{"ab", "reddit", false},     // too short
		{"tpo.pe", "reddit", false}, // has dot

		// Mastodon: alphanumeric and underscores only
		{"tpope", "mastodon", true},
		{"tim_pope", "mastodon", true},
		{"tpo.pe", "mastodon", false},   // has dot
		{"tim-pope", "mastodon", false}, // has hyphen

		// TikTok: 2-24 chars, alphanumeric, underscores, periods
		{"tpope", "tiktok", true},
		{"tpo.pe", "tiktok", true},
		{"a", "tiktok", false}, // too short

		// Bilibili: numeric IDs only
		{"123456", "bilibili", true},
		{"tpope", "bilibili", false}, // not numeric

		// VK: 5-32 chars
		{"tpope", "vkontakte", true},
		{"abcd", "vkontakte", false}, // too short (min 5)
	}

	for _, tt := range tests {
		name := tt.platform + "/" + tt.username
		t.Run(name, func(t *testing.T) {
			got := isValidUsernameForPlatform(tt.username, tt.platform)
			if got != tt.want {
				t.Errorf("isValidUsernameForPlatform(%q, %q) = %v, want %v",
					tt.username, tt.platform, got, tt.want)
			}
		})
	}
}

func TestGenerateCandidates_SkipsInvalidUsernames(t *testing.T) {
	// tpo.pe has a dot, which is invalid for LinkedIn, Twitter, GitHub, Reddit, Mastodon
	usernames := []string{"tpo.pe"}

	knownURLs := map[string]bool{}
	knownPlatforms := map[string]bool{}
	vouchedPlatforms := map[string]bool{}
	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms, vouchedPlatforms, DefaultMaxCandidatesPerPlatform)

	// Check that no LinkedIn candidate was generated (dots not allowed)
	for _, c := range candidates {
		if c.platform == "linkedin" && c.username == "tpo.pe" {
			t.Errorf("should not generate LinkedIn candidate for tpo.pe (dots not allowed)")
		}
		if c.platform == "twitter" && c.username == "tpo.pe" {
			t.Errorf("should not generate Twitter candidate for tpo.pe (dots not allowed)")
		}
		if c.platform == "mastodon" && c.username == "tpo.pe" {
			t.Errorf("should not generate Mastodon candidate for tpo.pe (dots not allowed)")
		}
	}

	// But TikTok and Instagram should allow dots
	var hasTikTok, hasInstagram bool
	for _, c := range candidates {
		if c.platform == "tiktok" && c.username == "tpo.pe" {
			hasTikTok = true
		}
		if c.platform == "instagram" && c.username == "tpo.pe" {
			hasInstagram = true
		}
	}
	if !hasTikTok {
		t.Errorf("should generate TikTok candidate for tpo.pe (dots allowed)")
	}
	if !hasInstagram {
		t.Errorf("should generate Instagram candidate for tpo.pe (dots allowed)")
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
				{Platform: "website", Username: "should_skip"},
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

func TestHasTechTitle(t *testing.T) {
	tests := []struct {
		name string
		bio  string
		want bool
	}{
		// Tech titles - should match
		{"software engineer", "Software Engineer at Google", true},
		{"developer", "Full-stack Developer", true},
		{"sre", "Site Reliability Engineer (SRE)", true},
		{"devops", "DevOps Engineer at Startup", true},
		{"architect", "Solutions Architect at AWS", true},
		{"cto", "CTO & Co-founder", true},
		{"ceo tech", "CEO at Holepunch", true},
		{"security", "Security Engineer | AppSec", true},
		{"open source", "Open Source maintainer", true},
		{"kubernetes", "Kubernetes contributor", true},
		{"golang", "Golang enthusiast", true},
		{"researcher", "ML Researcher at University", true},
		{"data scientist", "Data Scientist, ML Engineer", true},
		{"founder", "Founder & CEO at AppsCode Inc. Creator of KubeDB", true},
		{"creator", "I'm a creator of the SWC project", true},
		{"maintainer", "Volcano Maintainer", true},
		{"head of r&d", "Head of R&D Chengdu at DaoCloud", true},
		{"customer success", "Customer Success at Chainguard", true},
		{"technical support", "Senior Technical Support Engineer", true},
		{"tech company chainguard", "Product Manager at Chainguard", true},
		{"tech company google", "Recruiter at Google", true},

		// Non-tech titles - should NOT match
		{"lawyer", "Partner at King & Wood Mallesons", false},
		{"career coach", "Career Coach & Social Selling Expert", false},
		{"sales", "Sales Director at BigCorp", false},
		{"marketing", "VP Marketing", false},
		{"hr", "HR Manager", false},
		{"accountant", "CPA, Senior Accountant", false},
		{"teacher", "High School Teacher", false},
		{"doctor", "MD, Cardiologist", false},
		{"real estate", "Real Estate Agent", false},
		{"consultant", "Management Consultant at McKinsey", false},
		{"empty bio", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasTechTitle(tt.bio)
			if got != tt.want {
				t.Errorf("hasTechTitle(%q) = %v, want %v", tt.bio, got, tt.want)
			}
		})
	}
}

func TestGenerateCandidates_NoLinkedInGuessing(t *testing.T) {
	// LinkedIn guessing is disabled - we can't verify profiles without auth
	// LinkedIn profiles should only come from actual links
	usernames := []string{"dlorenc"}
	names := []string{"Dan Lorenc"}

	knownURLs := map[string]bool{}
	knownPlatforms := map[string]bool{}
	vouchedPlatforms := map[string]bool{}

	candidates := generateCandidates(usernames, names, knownURLs, knownPlatforms, vouchedPlatforms, DefaultMaxCandidatesPerPlatform)

	// Should not generate any LinkedIn candidates
	for _, c := range candidates {
		if c.platform == "linkedin" {
			t.Errorf("generateCandidates should not include LinkedIn (guessing disabled), got: %s", c.url)
		}
	}
}

func TestExtractNames(t *testing.T) {
	tests := []struct {
		name     string
		profiles []*profile.Profile
		want     []string
	}{
		{
			name: "extract names from profiles",
			profiles: []*profile.Profile{
				{Platform: "github", DisplayName: "Dan Lorenc"},
				{Platform: "twitter", DisplayName: "Dawid Lorenc"},
			},
			want: []string{"Dan Lorenc", "Dawid Lorenc"},
		},
		{
			name: "deduplicate names",
			profiles: []*profile.Profile{
				{Platform: "github", DisplayName: "Dan Lorenc"},
				{Platform: "twitter", DisplayName: "Dan Lorenc"},
			},
			want: []string{"Dan Lorenc"},
		},
		{
			name: "skip empty names",
			profiles: []*profile.Profile{
				{Platform: "github", DisplayName: ""},
				{Platform: "twitter", DisplayName: "Dan Lorenc"},
			},
			want: []string{"Dan Lorenc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNames(tt.profiles)
			if len(got) != len(tt.want) {
				t.Errorf("extractNames() returned %d names, want %d\ngot: %v\nwant: %v", len(got), len(tt.want), got, tt.want)
				return
			}
			for i, want := range tt.want {
				if got[i] != want {
					t.Errorf("extractNames()[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

func TestSlugifyName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"Dan Lorenc", "dan-lorenc"},
		{"Thomas Strömberg", "thomas-strmberg"},
		{"John  Doe", "john-doe"},             // Multiple spaces
		{" Jane Doe ", "jane-doe"},            // Leading/trailing spaces
		{"Bob", "bob"},                        // Single word - returns slugified
		{"Dan Lorenc, PMP", "dan-lorenc-pmp"}, // Comma becomes hyphen
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slugifyName(tt.name)
			if got != tt.want {
				t.Errorf("slugifyName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
