package substack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"standard", "https://username.substack.com", true},
		{"with path", "https://username.substack.com/about", true},
		{"at format", "https://substack.com/@username", true},
		{"at format with path", "https://substack.com/@username/posts", true},
		{"no protocol", "username.substack.com", true},
		{"uppercase", "HTTPS://USERNAME.SUBSTACK.COM", true},
		{"custom domain", "https://newsletter.com", false},
		{"other domain", "https://medium.com/@user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("AuthRequired() = true, want false")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"standard", "https://newsletter.substack.com", "newsletter"},
		{"at format", "https://substack.com/@johndoe", "johndoe"},
		{"at format with query", "https://substack.com/@johndoe?utm_source=copy", "johndoe"},
		{"with path", "https://johndoe.substack.com/p/post", "johndoe"},
		{"no protocol", "username.substack.com", "username"},
		{"about page", "https://author.substack.com/about", "author"},
		{"invalid", "https://substack.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
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
<html>
<head>
<title>About - The Sample Newsletter</title>
<meta name="description" content="Weekly insights on technology and startups.">
<meta property="og:image" content="https://substackcdn.com/image/fetch/avatar.jpg">
</head>
<body>
<span>10,234 subscribers</span>
<a href="https://twitter.com/author">Twitter</a>
<a href="https://github.com/author">GitHub</a>
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

	profile, err := client.Fetch(ctx, "https://sample.substack.com")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "substack" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "substack")
	}
	if profile.Username != "sample" {
		t.Errorf("Username = %q, want %q", profile.Username, "sample")
	}
	if profile.DisplayName != "The Sample Newsletter" {
		t.Errorf("Name = %q, want %q", profile.DisplayName, "The Sample Newsletter")
	}
	if profile.AvatarURL != "https://substackcdn.com/image/fetch/avatar.jpg" {
		t.Errorf("AvatarURL = %q, want %q", profile.AvatarURL, "https://substackcdn.com/image/fetch/avatar.jpg")
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
	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	_, err = client.Fetch(ctx, "https://nonexistent.substack.com")
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

	_, err = client.Fetch(ctx, "https://substack.com/invalid")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name            string
		html            string
		username        string
		wantName        string
		wantBio         string
		wantAvatar      string
		wantSubscribers string
	}{
		{
			name: "full profile",
			html: `<html><head>
				<title>About - Tech Insights</title>
				<meta name="description" content="Deep dives into technology trends.">
				<meta property="og:image" content="https://substackcdn.com/image/fetch/profile.jpg">
			</head><body>
				<span>5,000 subscribers</span>
				<a href="https://twitter.com/techinsights">Twitter</a>
			</body></html>`,
			username:        "techinsights",
			wantName:        "Tech Insights",
			wantBio:         "Deep dives into technology trends.",
			wantAvatar:      "https://substackcdn.com/image/fetch/profile.jpg",
			wantSubscribers: "5000",
		},
		{
			name: "JSON-LD profile",
			html: `<html><head>
				<script type="application/ld+json">
				{
					"@context": "https://schema.org",
					"@type": "Person",
					"name": "T Stromberg",
					"image": "https://substackcdn.com/image/fetch/avatar.jpg"
				}
				</script>
			</head><body></body></html>`,
			username:   "tstromberg",
			wantName:   "T Stromberg",
			wantAvatar: "https://substackcdn.com/image/fetch/avatar.jpg",
		},
		{
			name: "no about prefix",
			html: `<html><head>
				<title>Newsletter Name</title>
			</head><body></body></html>`,
			username: "newsletter",
			wantName: "Newsletter Name",
		},
		{
			name: "empty page uses username",
			html: `<html><head>
				<title></title>
			</head><body></body></html>`,
			username: "fallback",
			wantName: "fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseProfile(tt.html, "https://"+tt.username+".substack.com", tt.username)
			if err != nil {
				t.Fatalf("parseProfile() error = %v", err)
			}

			if profile.DisplayName != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.DisplayName, tt.wantName)
			}
			if tt.wantBio != "" && profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
			if tt.wantAvatar != "" && profile.AvatarURL != tt.wantAvatar {
				t.Errorf("AvatarURL = %q, want %q", profile.AvatarURL, tt.wantAvatar)
			}
			if tt.wantSubscribers != "" && profile.Fields["subscribers"] != tt.wantSubscribers {
				t.Errorf("subscribers = %q, want %q", profile.Fields["subscribers"], tt.wantSubscribers)
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
