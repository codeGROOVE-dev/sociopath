package codeberg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://codeberg.org/johwhj", true},
		{"https://codeberg.org/johwhj/", true},
		{"https://codeberg.org/timbran", true},
		{"https://codeberg.org/stephen-fox", true},
		{"https://CODEBERG.ORG/johwhj", true},
		{"https://codeberg.org/johwhj/repo", false}, // repo path, not profile
		{"https://codeberg.org/explore", false},     // system path
		{"https://codeberg.org/api", false},         // system path
		{"https://codeberg.org/", false},            // homepage
		{"https://github.com/johwhj", false},        // wrong platform
		{"https://example.com", false},              // unrelated
		{"https://codeberg.org/codeberg", false},    // Codeberg org itself
		{"https://codeberg.org/johwhj?tab=repositories", true},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := Match(tt.url)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("Codeberg should not require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://codeberg.org/johwhj", "johwhj"},
		{"https://codeberg.org/johwhj/", "johwhj"},
		{"https://codeberg.org/stephen-fox", "stephen-fox"},
		{"https://codeberg.org/timbran?tab=repositories", "timbran"},
		{"https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractUsername(tt.url)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
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

func TestFetch(t *testing.T) {
	mockHTML := `<!DOCTYPE html>
<html lang="en-US">
<head>
<title>Woohyun Joh - Codeberg.org</title>
<meta property="og:title" content="Woohyun Joh">
</head>
<body>
<div class="content tw-break-anywhere profile-avatar-name">
	<span class="header text center">Woohyun Joh</span>
	<span class="username">johwhj  · he/him</span>
</div>
<div>0 followers · 0 following</div>
<div>Joined on 2023-04-06</div>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockHTML)) //nolint:errcheck // test helper
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

	profile, err := client.Fetch(ctx, "https://codeberg.org/johwhj")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "codeberg" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "codeberg")
	}
	if profile.Username != "johwhj" {
		t.Errorf("Username = %q, want %q", profile.Username, "johwhj")
	}
	if profile.Name != "Woohyun Joh" {
		t.Errorf("Name = %q, want %q", profile.Name, "Woohyun Joh")
	}
}

type mockTransport struct {
	mockURL string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.mockURL[7:] // Strip "http://"
	return http.DefaultTransport.RoundTrip(req)
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
	client.httpClient = server.Client()

	_, err = client.Fetch(ctx, server.URL+"/nonexistent")
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

	_, err = client.Fetch(ctx, "https://example.com/nocodeberg")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseHTML(t *testing.T) {
	tests := []struct {
		name          string
		html          string
		username      string
		wantName      string
		wantPronouns  string
		wantCreatedAt string
	}{
		{
			name: "full profile with pronouns",
			html: `<html><head>
				<meta property="og:title" content="Woohyun Joh">
			</head><body>
				<span class="username">johwhj  · he/him</span>
				<div>0 followers · 0 following</div>
				<div>Joined on 2023-04-06</div>
			</body></html>`,
			username:      "johwhj",
			wantName:      "Woohyun Joh",
			wantPronouns:  "he/him",
			wantCreatedAt: "2023-04-06",
		},
		{
			name: "profile without pronouns",
			html: `<html><head>
				<meta property="og:title" content="stephen-fox">
			</head><body>
				<span class="username">stephen-fox</span>
				<div>Joined on 2025-02-15</div>
			</body></html>`,
			username:      "stephen-fox",
			wantName:      "stephen-fox",
			wantCreatedAt: "2025-02-15",
		},
		{
			name: "organization profile",
			html: `<html><head>
				<meta property="og:title" content="Timbran">
			</head><body>
				<span class="header text center">Timbran</span>
			</body></html>`,
			username: "timbran",
			wantName: "Timbran",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := parseHTML([]byte(tt.html), "https://codeberg.org/"+tt.username, tt.username)

			if profile.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.Name, tt.wantName)
			}
			if tt.wantPronouns != "" && profile.Fields["pronouns"] != tt.wantPronouns {
				t.Errorf("Pronouns = %q, want %q", profile.Fields["pronouns"], tt.wantPronouns)
			}
			if tt.wantCreatedAt != "" && profile.CreatedAt != tt.wantCreatedAt {
				t.Errorf("Joined = %q, want %q", profile.CreatedAt, tt.wantCreatedAt)
			}
		})
	}
}

func TestWithOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("with_logger", func(t *testing.T) {
		client, err := New(ctx, WithLogger(nil))
		if err != nil {
			t.Fatalf("New(WithLogger) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithLogger) returned nil")
		}
	})

	t.Run("with_cache", func(t *testing.T) {
		client, err := New(ctx, WithHTTPCache(nil))
		if err != nil {
			t.Fatalf("New(WithHTTPCache) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithHTTPCache) returned nil")
		}
	})
}

func TestNoSocialLinksExtracted(t *testing.T) {
	// This test verifies that the Codeberg parser does NOT extract
	// Codeberg's own footer links as social links
	mockHTML := `<!DOCTYPE html>
<html>
<head><meta property="og:title" content="Test User"></head>
<body>
<div class="profile-avatar-name">
	<span class="header">Test User</span>
</div>
<!-- Footer with Codeberg's own links that should NOT be extracted -->
<footer>
	<a href="https://social.anoxinon.de/@Codeberg">Mastodon</a>
	<a href="https://blog.codeberg.org">Blog</a>
	<a href="https://docs.codeberg.org">Docs</a>
</footer>
</body>
</html>`

	profile := parseHTML([]byte(mockHTML), "https://codeberg.org/testuser", "testuser")

	// Verify no social links were extracted
	if len(profile.SocialLinks) > 0 {
		t.Errorf("Expected no social links, got %v", profile.SocialLinks)
	}
}
