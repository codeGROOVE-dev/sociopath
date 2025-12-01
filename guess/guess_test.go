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

	vouchedPlatforms := map[string]bool{}
	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms, vouchedPlatforms)

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
	candidates := generateCandidates(usernames, nil, knownURLs, knownPlatforms, vouchedPlatforms)

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

func TestGenerateCandidates_SkipsLinkedInWhenVouched(t *testing.T) {
	// When we have a vouched LinkedIn profile, skip all LinkedIn guessing
	usernames := []string{"dlorenc"}
	names := []string{"Dan Lorenc"}

	knownURLs := map[string]bool{}
	knownPlatforms := map[string]bool{"linkedin": true}
	vouchedPlatforms := map[string]bool{"linkedin": true} // LinkedIn is vouched

	candidates := generateCandidates(usernames, names, knownURLs, knownPlatforms, vouchedPlatforms)

	// Should not generate any LinkedIn candidates
	for _, c := range candidates {
		if c.platform == "linkedin" {
			t.Errorf("generateCandidates should not include LinkedIn when vouched, got: %s", c.url)
		}
	}
}

func TestGenerateCandidates_AllowsNameBasedLinkedInWhenOnlyGuessed(t *testing.T) {
	// When we have a guessed LinkedIn (username match, may be wrong person),
	// still generate name-based LinkedIn candidates
	usernames := []string{"dlorenc"}
	names := []string{"Dan Lorenc"}

	knownURLs := map[string]bool{
		"linkedin.com/in/dlorenc": true, // Username-based guess already tried
	}
	knownPlatforms := map[string]bool{"linkedin": true} // Have a LinkedIn profile
	vouchedPlatforms := map[string]bool{}               // But NOT vouched

	candidates := generateCandidates(usernames, names, knownURLs, knownPlatforms, vouchedPlatforms)

	// Should generate name-based LinkedIn candidates (dan-lorenc, danlorenc)
	var linkedinCandidates []string
	for _, c := range candidates {
		if c.platform == "linkedin" {
			linkedinCandidates = append(linkedinCandidates, c.url)
		}
	}

	if len(linkedinCandidates) == 0 {
		t.Error("generateCandidates should generate name-based LinkedIn candidates when only guessed (not vouched)")
	}

	// Verify we got the expected name-based slugs
	foundDanLorenc := false
	foundDanlorenc := false
	for _, url := range linkedinCandidates {
		if url == "https://www.linkedin.com/in/dan-lorenc/" {
			foundDanLorenc = true
		}
		if url == "https://www.linkedin.com/in/danlorenc/" {
			foundDanlorenc = true
		}
	}
	if !foundDanLorenc {
		t.Error("expected dan-lorenc LinkedIn candidate")
	}
	if !foundDanlorenc {
		t.Error("expected danlorenc LinkedIn candidate")
	}
}

func TestGenerateCandidates_SkipsUsernameLinkedInWhenKnown(t *testing.T) {
	// Username-based LinkedIn guessing should be skipped when we have any LinkedIn profile
	usernames := []string{"dlorenc"}
	names := []string{} // No names, so no name-based guessing

	knownURLs := map[string]bool{}
	knownPlatforms := map[string]bool{"linkedin": true} // Have a LinkedIn profile (guessed)
	vouchedPlatforms := map[string]bool{}               // Not vouched

	candidates := generateCandidates(usernames, names, knownURLs, knownPlatforms, vouchedPlatforms)

	// Should NOT generate username-based LinkedIn candidates
	for _, c := range candidates {
		if c.platform == "linkedin" && c.matchType == "username" {
			t.Errorf("generateCandidates should skip username-based LinkedIn when knownPlatforms has linkedin, got: %s", c.url)
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
				{Platform: "github", Name: "Dan Lorenc"},
				{Platform: "twitter", Name: "Dawid Lorenc"},
			},
			want: []string{"Dan Lorenc", "Dawid Lorenc"},
		},
		{
			name: "deduplicate names",
			profiles: []*profile.Profile{
				{Platform: "github", Name: "Dan Lorenc"},
				{Platform: "twitter", Name: "Dan Lorenc"},
			},
			want: []string{"Dan Lorenc"},
		},
		{
			name: "skip empty names",
			profiles: []*profile.Profile{
				{Platform: "github", Name: ""},
				{Platform: "twitter", Name: "Dan Lorenc"},
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
