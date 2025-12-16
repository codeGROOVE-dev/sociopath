package devto

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
		{"https://dev.to/johndoe", true},
		{"https://dev.to/johndoe/", true},
		{"https://DEV.TO/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://example.com", false},
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
		t.Error("Dev.to should not require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://dev.to/johndoe", "johndoe"},
		{"https://dev.to/johndoe/", "johndoe"},
		{"https://dev.to/johndoe/article-title", "johndoe"},
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
<html>
<head>
<title>Ben Halpern - DEV Community</title>
<meta name="description" content="Founder of DEV. Working on better software for developers.">
</head>
<body>
<h1 class="crayons-title">Ben Halpern</h1>
<title>Location</title></svg><span>Brooklyn, NY</span>
<time datetime="2016-01-15T00:00:00Z">Jan 15, 2016</time>
<a href="https://twitter.com/bendhalpern" class="profile-header__meta__item">Twitter</a>
<a href="https://github.com/benhalpern">GitHub</a>
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
	// Use mockTransport to redirect requests to our test server
	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	// Use a URL that contains "dev.to" so extractUsername works
	profile, err := client.Fetch(ctx, "https://dev.to/ben")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "devto" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "devto")
	}
	if profile.Username != "ben" {
		t.Errorf("Username = %q, want %q", profile.Username, "ben")
	}
	if profile.DisplayName != "Ben Halpern" {
		t.Errorf("Name = %q, want %q", profile.DisplayName, "Ben Halpern")
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

	_, err = client.Fetch(ctx, "https://example.com/nodevto")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseHTML(t *testing.T) {
	tests := []struct {
		name         string
		html         string
		username     string
		wantName     string
		wantBio      string
		wantLocation string
	}{
		{
			name: "full profile",
			html: `<html><head>
				<title>Jane Doe - DEV Community</title>
				<meta name="description" content="Software Engineer. Open source enthusiast.">
			</head><body>
				<h1 class="crayons-title">Jane Doe</h1>
				<title>Location</title></svg><span>San Francisco, CA</span>
				<time datetime="2020-03-15">Mar 15, 2020</time>
			</body></html>`,
			username:     "janedoe",
			wantName:     "Jane Doe",
			wantBio:      "Software Engineer. Open source enthusiast.",
			wantLocation: "San Francisco, CA",
		},
		{
			name: "fallback to og:title",
			html: `<html><head>
				<title>John Smith - DEV Community</title>
			</head><body></body></html>`,
			username: "johnsmith",
			wantName: "John Smith",
		},
		{
			name:     "minimal profile",
			html:     `<html><head><title>DEV Community</title></head><body></body></html>`,
			username: "minuser",
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := parseHTML([]byte(tt.html), "https://dev.to/"+tt.username, tt.username)

			if profile.DisplayName != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.DisplayName, tt.wantName)
			}
			if tt.wantBio != "" && profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
			if tt.wantLocation != "" && profile.Location != tt.wantLocation {
				t.Errorf("Location = %q, want %q", profile.Location, tt.wantLocation)
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
