package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://github.com/torvalds", true},
		{"https://github.com/octocat", true},
		{"github.com/username", true},
		{"https://github.com/user123", true},
		{"https://github.com/features", false},
		{"https://github.com/marketplace", false},
		{"https://github.com/torvalds/linux", false}, // repo, not profile
		{"https://twitter.com/johndoe", false},
		{"https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/torvalds", "torvalds"},
		{"https://github.com/octocat", "octocat"},
		{"github.com/user_name", "user_name"},
		{"https://github.com/user?tab=repositories", "user"},
		{"https://www.github.com/someone", "someone"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseJSON(t *testing.T) {
	sampleJSON := `{
		"login": "octocat",
		"name": "The Octocat",
		"bio": "GitHub's mascot",
		"location": "San Francisco",
		"blog": "https://github.blog",
		"email": "octocat@github.com",
		"twitter_username": "github",
		"company": "@github",
		"public_repos": 8,
		"followers": 5000,
		"following": 9,
		"avatar_url": "https://avatars.githubusercontent.com/u/583231",
		"html_url": "https://github.com/octocat",
		"type": "User"
	}`

	p, err := parseJSON([]byte(sampleJSON), "https://github.com/octocat", "octocat")
	if err != nil {
		t.Fatalf("parseJSON failed: %v", err)
	}

	if p.Username != "octocat" {
		t.Errorf("Username = %q, want %q", p.Username, "octocat")
	}

	if p.DisplayName != "The Octocat" {
		t.Errorf("Name = %q, want %q", p.DisplayName, "The Octocat")
	}

	if p.Bio != "GitHub's mascot" {
		t.Errorf("Bio = %q, want %q", p.Bio, "GitHub's mascot")
	}

	if p.Location != "San Francisco" {
		t.Errorf("Location = %q, want %q", p.Location, "San Francisco")
	}

	if p.Website != "https://github.blog" {
		t.Errorf("Website = %q, want %q", p.Website, "https://github.blog")
	}

	if p.Fields["email"] != "octocat@github.com" {
		t.Errorf("email = %q, want %q", p.Fields["email"], "octocat@github.com")
	}

	if p.Fields["company"] != "github" {
		t.Errorf("company = %q, want %q", p.Fields["company"], "github")
	}

	if p.Fields["twitter"] != "https://twitter.com/github" {
		t.Errorf("twitter = %q, want %q", p.Fields["twitter"], "https://twitter.com/github")
	}

	if p.Fields["type"] != "User" {
		t.Errorf("type = %q, want %q", p.Fields["type"], "User")
	}

	if len(p.SocialLinks) != 1 {
		t.Errorf("SocialLinks length = %d, want 1", len(p.SocialLinks))
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("GitHub should not require auth")
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}
}

type mockTransport struct {
	mockURL string
}

func (mt *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = mt.mockURL[7:] // Strip "http://"
	return http.DefaultTransport.RoundTrip(req)
}

func TestFetch(t *testing.T) {
	apiJSON := `{
		"login": "testuser",
		"name": "Test User",
		"bio": "Test bio",
		"location": "Test City",
		"blog": "https://testuser.dev",
		"twitter_username": "testuser",
		"company": "@testcompany",
		"public_repos": 10,
		"followers": 100,
		"following": 50,
		"avatar_url": "https://avatars.githubusercontent.com/u/12345",
		"html_url": "https://github.com/testuser",
		"type": "User"
	}`

	htmlContent := `<!DOCTYPE html>
<html>
<head><title>testuser (Test User)</title></head>
<body>
<article class="markdown-body entry-content">
<p>Welcome to my profile!</p>
<a href="https://twitter.com/testuser">Twitter</a>
</article>
<a rel="nofollow me" href="https://mastodon.social/@testuser">Mastodon</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/testuser" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(apiJSON)) //nolint:errcheck // test helper
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(htmlContent)) //nolint:errcheck // test helper
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	profile, err := client.Fetch(ctx, "https://github.com/testuser")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "github" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "github")
	}
	if profile.Username != "testuser" {
		t.Errorf("Username = %q, want %q", profile.Username, "testuser")
	}
	if profile.DisplayName != "Test User" {
		t.Errorf("Name = %q, want %q", profile.DisplayName, "Test User")
	}
	if profile.Website != "https://testuser.dev" {
		t.Errorf("Website = %q, want %q", profile.Website, "https://testuser.dev")
	}
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	_, err = client.Fetch(ctx, "https://github.com/nonexistent")
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestFetch_InvalidUsername(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "https://twitter.com/someone")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestExtractREADMEHTML(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantLen int // minimum expected length, 0 = empty
	}{
		{
			name:    "with readme",
			html:    `<article class="markdown-body entry-content"><h1>Hello World</h1><p>Welcome to my profile</p></article>`,
			wantLen: 10,
		},
		{
			name:    "no readme",
			html:    `<html><body>No readme here</body></html>`,
			wantLen: 0,
		},
		{
			name:    "empty readme",
			html:    `<article class="markdown-body entry-content">   </article>`,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractREADMEHTML(tt.html)
			if tt.wantLen == 0 && got != "" {
				t.Errorf("extractREADMEHTML() = %q, want empty", got)
			}
			if tt.wantLen > 0 && len(got) < tt.wantLen {
				t.Errorf("extractREADMEHTML() length = %d, want at least %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestExtractSocialLinks(t *testing.T) {
	tests := []struct {
		name string
		html string
		want int // number of expected links
	}{
		{
			name: "rel me links",
			html: `<a rel="nofollow me" href="https://mastodon.social/@user">Mastodon</a>
				   <a rel="nofollow me" href="https://twitter.com/user">Twitter</a>`,
			want: 2,
		},
		{
			name: "href first then rel",
			html: `<a href="https://mastodon.social/@user" rel="nofollow me">Mastodon</a>`,
			want: 1,
		},
		{
			name: "skip github links",
			html: `<a rel="me" href="https://github.com/other">GitHub</a>
				   <a rel="me" href="https://twitter.com/user">Twitter</a>`,
			want: 1,
		},
		{
			name: "skip email links",
			html: `<a rel="me" href="mailto:test@example.com">Email</a>
				   <a rel="me" href="https://twitter.com/user">Twitter</a>`,
			want: 1,
		},
		{
			name: "no rel me links",
			html: `<a href="https://twitter.com/user">Twitter</a>`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSocialLinks(tt.html)
			if len(got) != tt.want {
				t.Errorf("extractSocialLinks() returned %d links, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractOrganizations(t *testing.T) {
	tests := []struct {
		name string
		html string
		want int
	}{
		{
			name: "with orgs",
			html: `<a aria-label="golang" href="/golang"><img alt="@golang"></a>
				   <a aria-label="kubernetes" href="/kubernetes"><img alt="@kubernetes"></a>`,
			want: 2,
		},
		{
			name: "no orgs",
			html: `<html><body>No organizations</body></html>`,
			want: 0,
		},
		{
			name: "duplicate orgs",
			html: `<a aria-label="golang" href="/golang"><img alt="@golang"></a>
				   <a aria-label="golang" href="/golang"><img alt="@golang"></a>`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractOrganizations(tt.html)
			if len(got) != tt.want {
				t.Errorf("extractOrganizations() returned %d orgs, want %d", len(got), tt.want)
			}
		})
	}
}

func TestFilterSamePlatformLinks(t *testing.T) {
	links := []string{
		"https://github.com/user",
		"https://twitter.com/user",
		"https://mastodon.social/@user",
	}

	filtered := filterSamePlatformLinks(links)
	if len(filtered) != 2 {
		t.Errorf("filterSamePlatformLinks() returned %d links, want 2", len(filtered))
	}

	for _, link := range filtered {
		if Match(link) {
			t.Errorf("filterSamePlatformLinks() should have removed %q", link)
		}
	}
}

func TestDedupeLinks(t *testing.T) {
	links := []string{
		"https://twitter.com/user",
		"https://TWITTER.COM/user/",
		"https://mastodon.social/@user",
		"https://twitter.com/user",
	}

	deduped := dedupeLinks(links)
	if len(deduped) != 2 {
		t.Errorf("dedupeLinks() returned %d links, want 2", len(deduped))
	}
}

func TestExtractUTCOffset(t *testing.T) {
	tests := []struct {
		name string
		html string
		want *float64
	}{
		{
			name: "negative offset (PST)",
			html: `<profile-timezone class="color-fg-muted" data-hours-ahead-of-utc="-8.0">(UTC -08:00)</profile-timezone>`,
			want: ptr(-8.0),
		},
		{
			name: "negative offset (Hawaii)",
			html: `<profile-timezone class="color-fg-muted d-inline" data-hours-ahead-of-utc="-11.0">(UTC -11:00)</profile-timezone>`,
			want: ptr(-11.0),
		},
		{
			name: "positive offset (IST)",
			html: `<profile-timezone data-hours-ahead-of-utc="5.5">(UTC +05:30)</profile-timezone>`,
			want: ptr(5.5),
		},
		{
			name: "zero offset (UTC)",
			html: `<profile-timezone data-hours-ahead-of-utc="0">(UTC +00:00)</profile-timezone>`,
			want: ptr(0.0),
		},
		{
			name: "positive offset (CET)",
			html: `<profile-timezone data-hours-ahead-of-utc="1">(UTC +01:00)</profile-timezone>`,
			want: ptr(1.0),
		},
		{
			name: "fractional offset (Nepal)",
			html: `<profile-timezone data-hours-ahead-of-utc="5.75">(UTC +05:45)</profile-timezone>`,
			want: ptr(5.75),
		},
		{
			name: "no profile-timezone element",
			html: `<div class="profile-info">No timezone here</div>`,
			want: nil,
		},
		{
			name: "empty data-hours-ahead-of-utc",
			html: `<profile-timezone data-hours-ahead-of-utc="">(UTC)</profile-timezone>`,
			want: nil,
		},
		{
			name: "embedded in full page",
			html: `<!DOCTYPE html><html><body>
				<div class="sidebar">
					<profile-timezone class="color-fg-muted d-inline" data-hours-ahead-of-utc="-7.0">(UTC -07:00)</profile-timezone>
				</div>
			</body></html>`,
			want: ptr(-7.0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUTCOffset(tt.html)
			if tt.want == nil {
				if got != nil {
					t.Errorf("extractUTCOffset() = %v, want nil", *got)
				}
			} else {
				if got == nil {
					t.Errorf("extractUTCOffset() = nil, want %v", *tt.want)
				} else if *got != *tt.want {
					t.Errorf("extractUTCOffset() = %v, want %v", *got, *tt.want)
				}
			}
		})
	}
}

func ptr(f float64) *float64 {
	return &f
}

func TestParseJSON_WithEmailInBlog(t *testing.T) {
	// Test case where blog field contains an email (which should be extracted)
	sampleJSON := `{
		"login": "emailuser",
		"name": "Email User",
		"bio": "Test",
		"blog": "mailto:user@company.io"
	}`

	p, err := parseJSON([]byte(sampleJSON), "https://github.com/emailuser", "emailuser")
	if err != nil {
		t.Fatalf("parseJSON failed: %v", err)
	}

	if p.Fields["email"] != "user@company.io" {
		t.Errorf("email = %q, want %q", p.Fields["email"], "user@company.io")
	}
	if p.Website != "" {
		t.Errorf("Website should be empty when blog is an email, got %q", p.Website)
	}
}

func TestParseJSON_BlogWithoutProtocol(t *testing.T) {
	sampleJSON := `{
		"login": "noprotocol",
		"name": "No Protocol",
		"blog": "example.com"
	}`

	p, err := parseJSON([]byte(sampleJSON), "https://github.com/noprotocol", "noprotocol")
	if err != nil {
		t.Fatalf("parseJSON failed: %v", err)
	}

	if p.Website != "https://example.com" {
		t.Errorf("Website = %q, want %q", p.Website, "https://example.com")
	}
}

func TestParseJSON_InvalidJSON(t *testing.T) {
	_, err := parseJSON([]byte("not valid json"), "https://github.com/user", "user")
	if err == nil {
		t.Error("parseJSON() expected error for invalid JSON, got nil")
	}
}

func TestWithOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("with_cache", func(t *testing.T) {
		client, err := New(ctx, WithHTTPCache(nil))
		if err != nil {
			t.Fatalf("New(WithHTTPCache) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithHTTPCache) returned nil")
		}
	})

	t.Run("with_logger", func(t *testing.T) {
		client, err := New(ctx, WithLogger(nil))
		if err != nil {
			t.Fatalf("New(WithLogger) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithLogger) returned nil")
		}
	})
}

func TestParseProfileFromHTML(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Sample HTML based on github.com/tstromberg profile structure
	sampleHTML := `
<html>
<head><title>tstromberg</title></head>
<body>
<img style="height:auto;" src="https://avatars.githubusercontent.com/u/101424?v=4" width="260" height="260" class="avatar avatar-user width-full border color-bg-default" />
<span class="p-name vcard-fullname d-block overflow-hidden" itemprop="name">
Thomas Stromberg
</span>
<span class="p-nickname vcard-username d-block" itemprop="additionalName">tstromberg</span>
<div class="p-note user-profile-bio mb-3 js-user-profile-bio f4" data-bio-text="CEO @ codeGROOVE">
CEO @ codeGROOVE
</div>
<li class="vcard-detail pt-1" itemprop="homeLocation" aria-label="Home location: McMurdo Station, Antarctica">
<svg class="octicon octicon-location"></svg>
<span>McMurdo Station, Antarctica</span>
</li>
<li itemprop="url" data-test-selector="profile-website-url" class="vcard-detail pt-1">
<svg class="octicon octicon-link"></svg>
<a rel="nofollow me" class="Link--primary" href="http://localhost:8080/">http://localhost:8080/</a>
</li>
</body>
</html>
`

	tests := []struct {
		name     string
		html     string
		urlStr   string
		username string
		wantName string
		wantBio  string
		wantLoc  string
		wantWeb  string
	}{
		{
			name:     "full_profile",
			html:     sampleHTML,
			urlStr:   "https://github.com/tstromberg",
			username: "tstromberg",
			wantName: "Thomas Stromberg",
			wantBio:  "CEO @ codeGROOVE",
			wantLoc:  "McMurdo Station, Antarctica",
			wantWeb:  "http://localhost:8080/",
		},
		{
			name: "minimal_profile",
			html: `
<span class="p-name vcard-fullname" itemprop="name">Jane Doe</span>
<div data-bio-text="Developer">Developer</div>
`,
			urlStr:   "https://github.com/janedoe",
			username: "janedoe",
			wantName: "Jane Doe",
			wantBio:  "Developer",
			wantLoc:  "",
			wantWeb:  "",
		},
		{
			name:     "empty_html",
			html:     "<html><body></body></html>",
			urlStr:   "https://github.com/nobody",
			username: "nobody",
			wantName: "",
			wantBio:  "",
			wantLoc:  "",
			wantWeb:  "",
		},
		{
			name: "website_without_protocol",
			html: `
<li itemprop="url" data-test-selector="profile-website-url">
<a href="example.com">example.com</a>
</li>
`,
			urlStr:   "https://github.com/user",
			username: "user",
			wantName: "",
			wantBio:  "",
			wantLoc:  "",
			wantWeb:  "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prof := client.parseProfileFromHTML(ctx, tt.html, tt.urlStr, tt.username)

			if prof.Platform != "github" {
				t.Errorf("Platform = %q, want %q", prof.Platform, "github")
			}
			if prof.URL != tt.urlStr {
				t.Errorf("URL = %q, want %q", prof.URL, tt.urlStr)
			}
			if prof.Username != tt.username {
				t.Errorf("Username = %q, want %q", prof.Username, tt.username)
			}
			if prof.DisplayName != tt.wantName {
				t.Errorf("Name = %q, want %q", prof.DisplayName, tt.wantName)
			}
			if prof.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", prof.Bio, tt.wantBio)
			}
			if prof.Location != tt.wantLoc {
				t.Errorf("Location = %q, want %q", prof.Location, tt.wantLoc)
			}
			if prof.Website != tt.wantWeb {
				t.Errorf("Website = %q, want %q", prof.Website, tt.wantWeb)
			}
		})
	}
}

func TestAPIError(t *testing.T) {
	t.Run("rate_limit_error", func(t *testing.T) {
		err := &APIError{
			StatusCode:  403,
			IsRateLimit: true,
			Message:     "rate limit exceeded",
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "rate limited") {
			t.Errorf("Error() = %q, want to contain 'rate limited'", errStr)
		}
	})

	t.Run("other_error", func(t *testing.T) {
		err := &APIError{
			StatusCode:  401,
			IsRateLimit: false,
			Message:     "bad credentials",
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "401") {
			t.Errorf("Error() = %q, want to contain '401'", errStr)
		}
	})
}

func TestExtractAchievementsMap(t *testing.T) {
	tests := []struct {
		name string
		html string
		want map[string]string
	}{
		{
			name: "tiered achievement",
			html: `<img alt="Achievement: Pair Extraordinaire" class="achievement-badge-sidebar"><span class="achievement-tier-label achievement-tier-label--gold">x4</span>`,
			want: map[string]string{"Pair Extraordinaire": "4"},
		},
		{
			name: "simple achievement",
			html: `<img alt="Achievement: Mars 2020 Contributor" class="achievement-badge-sidebar">`,
			want: map[string]string{"Mars 2020 Contributor": "1"},
		},
		{
			name: "multiple achievements",
			html: `<img alt="Achievement: Pull Shark" class="achievement-badge-sidebar"><span class="achievement-tier-label achievement-tier-label--bronze">x2</span>` +
				`<img alt="Achievement: Arctic Code Vault Contributor" class="achievement-badge-sidebar">`,
			want: map[string]string{"Pull Shark": "2", "Arctic Code Vault Contributor": "1"},
		},
		{
			name: "no achievements",
			html: `<div>No achievements here</div>`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAchievementsMap(tt.html)
			if tt.want == nil {
				if got != nil {
					t.Errorf("extractAchievementsMap() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("extractAchievementsMap() returned %d badges, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("extractAchievementsMap()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
